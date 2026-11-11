# Active Directory User Management
# Requires the ActiveDirectory PowerShell module and appropriate AD permissions.

try {
    Import-Module ActiveDirectory -ErrorAction Stop

    # Convert the discovered hostname into a plain string for -Server.
    $domainController = Get-ADDomainController -Discover -Writable `
        -ErrorAction Stop

    $server = [string](
        $domainController.HostName |
            Select-Object -First 1
    )

    if ([string]::IsNullOrWhiteSpace($server)) {
        throw "Unable to determine a domain controller hostname."
    }

    Write-Host "Using domain controller: $server" -ForegroundColor Cyan
}
catch {
    Write-Error "Unable to initialize Active Directory: $($_.Exception.Message)"
    return
}

$userIdentity = $null

while ($true) {
    try {
        # Select a user when starting or switching accounts.
        if (-not $userIdentity) {
            Write-Host "`nSearch by one or more fields. Leave unused fields blank."
            Write-Host "Partial values match the beginning of a field (example: Jon finds Jonathan)."

            $searchUsername = (Read-Host "Username").Trim()
            $searchFirst = (Read-Host "First name").Trim()
            $searchLast = (Read-Host "Last name").Trim()

            # Escape LDAP special characters so input is treated literally.
            # A trailing wildcard is added by the script for prefix matching.
            $criteria = @(
                @{ Attribute = 'sAMAccountName'; Value = $searchUsername }
                @{ Attribute = 'givenName'; Value = $searchFirst }
                @{ Attribute = 'sn'; Value = $searchLast }
            )

            $clauses = @(
                foreach ($criterion in $criteria) {
                    if (-not [string]::IsNullOrWhiteSpace($criterion.Value)) {
                        $escaped = $criterion.Value.Replace('\', '\5c').Replace(
                            '*', '\2a').Replace('(', '\28').Replace(
                            ')', '\29').Replace([string][char]0, '\00')
                        '({0}={1}*)' -f $criterion.Attribute, $escaped
                    }
                }
            )

            if ($clauses.Count -eq 0) {
                Write-Warning "Enter at least one search field."
                continue
            }

            # When several fields are supplied, ALL must match.
            $ldapFilter = if ($clauses.Count -eq 1) {
                $clauses[0]
            }
            else {
                '(&' + ($clauses -join '') + ')'
            }

            $foundUsers = @(
                Get-ADUser -LDAPFilter $ldapFilter -Server $server `
                    -Properties DisplayName, Department, Office `
                    -ErrorAction Stop |
                    Sort-Object Surname, GivenName, SamAccountName
            )

            if ($foundUsers.Count -eq 0) {
                Write-Warning "No users matched. Try fewer fields or a shorter name."
                continue
            }

            # Always show a numbered selection, even for one match.
            $rows = for ($i = 0; $i -lt $foundUsers.Count; $i++) {
                [PSCustomObject]@{
                    Number = $i + 1
                    Name = $foundUsers[$i].Name
                    Username = $foundUsers[$i].SamAccountName
                    Enabled = $foundUsers[$i].Enabled
                    Department = $foundUsers[$i].Department
                    Office = $foundUsers[$i].Office
                }
            }
            $rows | Format-Table -AutoSize -Wrap | Out-Host

            $selection = 0
            while ($true) {
                $selectionInput = Read-Host "Select user number (0 to search again)"
                if ([int]::TryParse($selectionInput, [ref]$selection) -and
                    $selection -ge 0 -and $selection -le $foundUsers.Count) {
                    break
                }
                Write-Warning "Enter a number from 0 through $($foundUsers.Count)."
            }

            if ($selection -eq 0) {
                continue
            }

            $userIdentity = $foundUsers[$selection - 1].ObjectGUID
        }

        # Refresh the selected account's status.
        $user = Get-ADUser -Identity $userIdentity -Server $server `
            -Properties LockedOut -ErrorAction Stop

        Write-Host "`n============================================" -ForegroundColor Cyan
        Write-Host "Selected user: $($user.Name)"
        Write-Host "Username:      $($user.SamAccountName)"
        Write-Host "Enabled:       $($user.Enabled)"
        Write-Host "Locked out:    $($user.LockedOut)"
        Write-Host "============================================" -ForegroundColor Cyan

        Write-Host "1. Reset user password"
        Write-Host "2. Disable account"
        Write-Host "3. View locked status"
        Write-Host "4. Unlock account"
        Write-Host "5. View account details and group membership"
        Write-Host "6. Select another user"
        Write-Host "0. Exit"

        $choice = (Read-Host "`nSelect an option").Trim()

        switch ($choice) {
            '1' {
                $confirm = Read-Host "Reset password for '$($user.SamAccountName)'? (Y/N)"

                if ($confirm.Trim() -notin @('Y', 'Yes')) {
                    Write-Host "Password reset canceled."
                    break
                }

                $mustChange = (
                    Read-Host "Require password change at next sign-in? (Y/N)"
                ).Trim()

                if ($mustChange -notin @('Y', 'Yes', 'N', 'No')) {
                    Write-Warning "Enter Y or N. Password reset canceled."
                    break
                }

                $requireChange = $mustChange -in @('Y', 'Yes')

                $passwordSettings = Get-ADUser -Identity $userIdentity `
                    -Server $server -Properties PasswordNeverExpires `
                    -ErrorAction Stop

                if ($requireChange -and $passwordSettings.PasswordNeverExpires) {
                    Write-Warning "Password never expires is enabled. Review that setting before requiring a password change at next sign-in."
                    break
                }

                $newPassword = Read-Host "Enter the new password" -AsSecureString

                try {
                    if ($newPassword.Length -eq 0) {
                        throw "Password cannot be blank."
                    }

                    Set-ADAccountPassword -Identity $userIdentity `
                        -Server $server -Reset -NewPassword $newPassword `
                        -ErrorAction Stop

                    Write-Host "Password successfully reset." -ForegroundColor Green
                }
                finally {
                    $newPassword.Dispose()
                    Remove-Variable newPassword -ErrorAction SilentlyContinue
                }

                # Report this separately because the password has already changed.
                try {
                    Set-ADUser -Identity $userIdentity -Server $server `
                        -ChangePasswordAtLogon $requireChange `
                        -ErrorAction Stop

                    Write-Host "Require change at next sign-in: $requireChange" `
                        -ForegroundColor Green
                }
                catch {
                    Write-Warning "Password was reset, but the next-sign-in setting could not be updated: $($_.Exception.Message)"
                }
            }

            '2' {
                if (-not $user.Enabled) {
                    Write-Host "Account is already disabled." -ForegroundColor Yellow
                    break
                }

                $confirm = Read-Host "Type '$($user.SamAccountName)' to confirm disabling this account"

                if ($confirm.Trim() -ne $user.SamAccountName) {
                    Write-Host "Disable canceled."
                    break
                }

                Disable-ADAccount -Identity $userIdentity -Server $server `
                    -ErrorAction Stop

                $updated = Get-ADUser -Identity $userIdentity `
                    -Server $server -ErrorAction Stop

                if (-not $updated.Enabled) {
                    Write-Host "Account successfully disabled." -ForegroundColor Green
                }
                else {
                    Write-Warning "Account still reports as enabled."
                }
            }

            '3' {
                Get-ADUser -Identity $userIdentity -Server $server `
                    -Properties LockedOut -ErrorAction Stop |
                    Select-Object Name, SamAccountName, Enabled, LockedOut |
                    Format-Table -AutoSize
            }

            '4' {
                if (-not $user.LockedOut) {
                    Write-Host "Account is not locked." -ForegroundColor Green
                    break
                }

                $confirm = Read-Host "Unlock '$($user.SamAccountName)'? (Y/N)"

                if ($confirm.Trim() -notin @('Y', 'Yes')) {
                    Write-Host "Unlock canceled."
                    break
                }

                Unlock-ADAccount -Identity $userIdentity -Server $server `
                    -ErrorAction Stop

                $updated = Get-ADUser -Identity $userIdentity `
                    -Server $server -Properties LockedOut -ErrorAction Stop

                if ($updated.LockedOut) {
                    Write-Warning "Account is still locked or has been locked again."
                }
                else {
                    Write-Host "Account successfully unlocked." -ForegroundColor Green
                }
            }

            '5' {
                $properties = @(
                    'DisplayName'
                    'Description'
                    'EmailAddress'
                    'Department'
                    'Title'
                    'Office'
                    'OfficePhone'
                    'LockedOut'
                    'AccountExpirationDate'
                    'PasswordLastSet'
                    'PasswordNeverExpires'
                    'PasswordExpired'
                    'PasswordNotRequired'
                    'CannotChangePassword'
                    'LastLogonDate'
                    'Created'
                    'Modified'
                    'HomeDirectory'
                    'HomeDrive'
                    'ScriptPath'
                    'ProfilePath'
                    'LogonWorkstations'
                    'pwdLastSet'
                    'msDS-UserPasswordExpiryTimeComputed'
                )

                $details = Get-ADUser -Identity $userIdentity `
                    -Server $server -Properties $properties `
                    -ErrorAction Stop

                $expiryValue = $details.'msDS-UserPasswordExpiryTimeComputed'

                $passwordExpiry = if ($details.PasswordNeverExpires) {
                    'Never'
                }
                elseif ($null -eq $expiryValue -or
                        $expiryValue -eq 0 -or
                        $expiryValue -eq [long]::MaxValue) {
                    'Not available / not applicable'
                }
                else {
                    [datetime]::FromFileTime([long]$expiryValue)
                }

                [PSCustomObject]@{
                    Name                   = $details.Name
                    DisplayName            = $details.DisplayName
                    Username               = $details.SamAccountName
                    UserPrincipalName      = $details.UserPrincipalName
                    Description            = $details.Description
                    Email                  = $details.EmailAddress
                    Department             = $details.Department
                    Title                  = $details.Title
                    Office                 = $details.Office
                    Phone                  = $details.OfficePhone
                    AccountEnabled         = $details.Enabled
                    LockedOut              = $details.LockedOut
                    AccountExpires         = $details.AccountExpirationDate
                    PasswordLastSet        = $details.PasswordLastSet
                    PasswordExpires        = $passwordExpiry
                    PasswordNeverExpires   = $details.PasswordNeverExpires
                    PasswordExpired        = $details.PasswordExpired
                    PasswordRequired       = -not $details.PasswordNotRequired
                    UserCanChangePassword  = -not $details.CannotChangePassword
                    MustChangeAtNextSignIn = ($details.pwdLastSet -eq 0)
                    LastLogonApproximate   = $details.LastLogonDate
                    AccountCreated         = $details.Created
                    LastModified           = $details.Modified
                    HomeDirectory          = $details.HomeDirectory
                    HomeDrive              = $details.HomeDrive
                    LogonScript            = $details.ScriptPath
                    ProfilePath            = $details.ProfilePath
                    LogonWorkstations      = $details.LogonWorkstations
                    DistinguishedName      = $details.DistinguishedName
                } | Format-List

                Write-Host "`nAD group membership:" -ForegroundColor Cyan

                Get-ADPrincipalGroupMembership -Identity $userIdentity `
                    -Server $server -ErrorAction Stop |
                    Sort-Object Name |
                    Select-Object Name, GroupScope, GroupCategory |
                    Format-Table -AutoSize
            }

            '6' {
                $userIdentity = $null
            }

            '0' {
                Write-Host "Exiting."
                return
            }

            default {
                Write-Warning "Select an option from 0 through 6."
            }
        }
    }
    catch {
        Write-Warning "Operation failed: $($_.Exception.Message)"
    }
}