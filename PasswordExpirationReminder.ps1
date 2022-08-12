#
# PasswordExpirationReminder.ps1
# By Jesse Dudgeon
# Last Updated: 8/12/2022
#
# Emails all users with less than $EMAIL_DAYS days before their password expires. Sets all
# users with a password expiring in less than $LAST_DAY days to ChangePasswordAtLogon
# Emails their direct supervisor on the last $SUPERVISOR_EMAIL_DAYS
# Randomizes and disables users whose password expires.
# Emails a report to ADMIN_EMAIL.

### Imports
Import-Module ActiveDirectory

# Load "System.Web" assembly in PowerShell console
Add-Type -AssemblyName System.Web

### Globals
$MAIL_FROM = "email@address.com"
$MAIL_SERVER = "tenant.mail.protection.outlook.com"
$MAIL_PORT = 25
$ADMIN_EMAIL = @('admin-email@address.com') # For reports
$LAST_DAY = 1
$EMAIL_DAYS = 14
$SUPERVISOR_EMAIL_DAYS = 5

$maxPasswordAgeTimeSpan = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge
$Today = Get-Date

$ExpiringPasswords = New-Object System.Collections.ArrayList
$LastDay = New-Object System.Collections.ArrayList
$ExpiredPasswords = New-Object System.Collections.ArrayList

Function EmailUserDaysLeft {
	param($User, $DaysLeft)
	$Email = $User.SamAccountName + "@address.com"
	$EmpName = $User.GivenName
	$ExpiryDate = $User.PasswordLastSet + $maxPasswordAgeTimeSpan
	$ExpiryDateStr = $ExpiryDate.ToString('dddd, MMMM d')
	$WarnMsgPre = "<p style='font-family: calibri'>Hi $EmpName,</p>"

	if ($DaysLeft -eq $LAST_DAY) {

		$WarnMsgExpiresIn = "<p style='font-family: calibri'>Your SCAN password is expiring. Please change it <strong>immediately</strong> by following these steps on your computer:</p>"
		$Subject = "[REQUIRES ACTION] Password Reminder: Your password is expiring."

	} Else {
		$WarnMsgExpiresIn = "<p style='font-family: calibri'>Your SCAN password will expire in $DaysLeft days. Please change it <strong>before $ExpiryDateStr</strong> by following these steps on your computer:</p>"
		$Subject = "[REQUIRES ACTION] Password Reminder: Your password will expire in $DaysLeft days."

	}

	$WarnMsgBody = "
		<ol style='font-family: calibri'>
			<li>Either be at the Main Street office in Fort Wayne <strong>OR</strong> connect to the VPN</li>
			<li>Press CTRL-ALT-DEL</li>
			<li>Select 'Change a password'</li>
		</ol>
		<p style='font-family: calibri'>Requirements for the password are as follows:</p>
		<ul style='font-family: calibri'>
			<li>Must be at least 10 characters long</li>
			<li>Must not contain your name</li>
			<li>Must not be one of your previous passwords</li>
			<li>Contain characters from three of the following four categories:</li>
			<li>Uppercase characters (A through Z)</li>
			<li>Lowercase characters (a through z)</li>
			<li>Numbers (0 through 9)</li>
			<li>Non-alphabetic characters (for example, !, $, #, %)</li>
		</ul>
		<p style='font-family: calibri'>As a reminder, you'll need to update your phone with your new password to continue to receive and send emails on your phone. Each phone is different, so if you have questions, please ask and let us know what type of phone you have. You may also get prompted by Outlook to update your password for email access.</p>
		<p style='font-family: calibri'><strong>Failure to change your password will prevent you from accessing emails and/or logging into your computer.</strong></p>
		<p style='font-family: calibri'>For assistance, feel free to email helpdesk@scaninc.org or call us at x623</p>
		<p style='font-family: calibri'>- SCAN, Inc. Information Systems Department</p>
	"

	$WarnMsg = $WarnMsgPre + $WarnMsgExpiresIn + $WarnMsgBody

	Send-MailMessage 
		-to $Email 
		-from $MAIL_FROM 
		-Subject $Subject 
		-body $WarnMsg 
		-smtpserver $MAIL_SERVER 
		-Port $MAIL_PORT 
		-BodyAsHtml
}

Function EmailSupervisorDaysLeft {
	param($User, $DaysLeft)
	$EmpFullName = $User.DisplayName
	$ExpiryDate = $User.PasswordLastSet + $maxPasswordAgeTimeSpan
	$ExpiryDateStr = $ExpiryDate.ToString('dddd, MMMM d')
	
	If (-Not $User.Manager) {
		# No Manager, exiting
		return
	}

	$Manager = Get-ADUser $User.Manager
	$ManagerName = $Manager.GivenName
	$ManagerEmail = $Manager.SamAccountName + "@scaninc.org"
	
	$WarnMsgPre = "<p style='font-family: calibri'>Hi $ManagerName,</p>"
	
	if ($DaysLeft -eq $LAST_DAY) {
		$WarnMsgExpiresIn = "<p style='font-family: calibri'>$EmpFullName's password is expiring today. Please help them change it <strong>immediately</strong> by following the instructions they received in an email.</p>"

		$Subject = "[REQUIRES ACTION] Supervisor Notice: $EmpFullName's password is expiring."
	} Else {
		$WarnMsgExpiresIn = "<p style='font-family: calibri'>$EmpFullName's password will expire in $DaysLeft days. Please help them change it <strong>before $ExpiryDateStr</strong> by following the instructions they received in an email.</p>"

		$Subject = "[REQUIRES ACTION] Supervisor Notice: $EmpFullName's password will expire in $DaysLeft days."
	}

	$WarnMsgBody = "
		<p style='font-family: calibri'>You are receiving this email because our records show that you are the direct supervisor of this person. If that is not correct, please email helpdesk@scaninc.org with their correct supervisor.</p>
		<p style='font-family: calibri'>Thank you!</p>
		<p style='font-family: calibri'>- SCAN, Inc. Information Systems Department</p>
	"

	$WarnMsg = $WarnMsgPre + $WarnMsgExpiresIn + $WarnMsgBody

	Send-MailMessage 
		-to $ManagerEmail 
		-from $MAIL_FROM 
		-Subject $Subject 
		-body $WarnMsg 
		-smtpserver $MAIL_SERVER 
		-Port $MAIL_PORT 
		-BodyAsHtml
}

Function SendAdminReport {
	If ($ExpiredPasswords.Count -gt 0) {
		$AdminEmailMsg += "<p style='font-family: calibri'><strong>These passwords expired, and have been reset and disabled:</strong></p>`r`n"
		$AdminEmailMsg += "<ul style='font-family: calibri'>`r`n"
		foreach ($User in $ExpiredPasswords) {
			$AdminEmailMsg += "<li>$($User)</li>`r`n"
		}
		$AdminEmailMsg += "</ul>`r`n"
	} Else {
		$AdminEmailMsg += "<p style='font-family: calibri'><strong>No users expired today.</strong></p>`r`n"
	}
	
	If ($LastDay.Count -gt 0) {
		$AdminEmailMsg += "<p style='font-family: calibri'><strong>Here is a list of users whose passwords are expired tomorrow:</strong></p>`r`n"
		$AdminEmailMsg += "<ul style='font-family: calibri'>`r`n"
		foreach ($User in $LastDay) {
			$AdminEmailMsg += "<li>$($User)</li>`r`n"
		}
		$AdminEmailMsg += "</ul>`r`n"
	} Else {
		$AdminEmailMsg += "<p style='font-family: calibri'><strong>No users have passwords expiring tomorrow.</strong></p>`r`n"
	}
	
	If ($ExpiringPasswords.Count -gt 0) {
		If ($ExpiringPasswords.Count -gt 1) {
			$ExpiringPasswords = $ExpiringPasswords | Sort-Object @{Expression={$_[1]}; Ascending=$True}
		}
	
		$AdminEmailMsg += "<p style='font-family: calibri'><strong>Here is a list of users whose passwords are expiring in the next 14 days:</strong></p>`r`n"
		$AdminEmailMsg += "<ul style='font-family: calibri'>`r`n"
		foreach ($User in $ExpiringPasswords) {
			$AdminEmailMsg += "<li>$($User[0]) - $($User[1])</li>`r`n"
		}
		$AdminEmailMsg += "</ul>`r`n"
	} Else {
		$AdminEmailMsg += "<p style='font-family: calibri'><strong>No users have passwords expiring in the next 14 days.</strong></p>`r`n"
	}
	
	$AdminSub = "[REPORT] Password Reminder: $($ExpiredPasswords.Count), $($LastDay.Count), $($ExpiringPasswords.Count)"
	
	Send-MailMessage 
		-to $ADMIN_EMAIL 
		-from $MAIL_FROM 
		-Subject $AdminSub 
		-body $AdminEmailMsg 
		-smtpserver $MAIL_SERVER 
		-Port $MAIL_PORT 
		-BodyAsHtml
}

Function ExpirePassword {
	param($User)
	$Username = $User.SamAccountName

	# Generate a 20 character random password, make it securestring
	$NewPassword = [System.Web.Security.Membership]::GeneratePassword(16,1)
	$NewPassword = $NewPassword + "Zj6^" # This guarentees complexity requirements are met.
	$SecureStringNewPassword = ConvertTo-SecureString -AsPlainText -Force -String $NewPassword

	# Change their password, disable their account.
	Set-ADAccountPassword $Username -NewPassword $SecureStringNewPassword -Reset
	Disable-ADAccount $Username
}


Get-ADUser -filter * -properties PasswordLastSet, PasswordExpired, PasswordNeverExpires, EmailAddress, GivenName, Enabled, Manager, DisplayName | ForEach-Object {
	$Username = $_.SamAccountName
	$Disabled = -not $_.Enabled


	if (!$_.PasswordNeverExpires -and !$Disabled) {
		$ExpiryDate = $_.PasswordLastSet + $maxPasswordAgeTimeSpan
		$DaysLeft = ($ExpiryDate - $Today).days

		if ($DaysLeft -lt $LAST_DAY) {

			# Their password expired and shouldn't be allowed to.
			$Null = $ExpiredPasswords.Add($Username)
			ExpirePassword -User $_

		} ElseIf ($DaysLeft -eq $LAST_DAY) {
			
			$Null = $LastDay.Add($Username)
			EmailUserDaysLeft -User $_ -DaysLeft $DaysLeft
			EmailSupervisorDaysLeft -User $_ -DaysLeft $DaysLeft

		} ElseIf ($DaysLeft -le $EMAIL_DAYS) {
			
			$Null = $ExpiringPasswords.Add(($Username, $Daysleft))
			EmailUserDaysLeft -User $_ -DaysLeft $DaysLeft

			If ($DaysLeft -le $SUPERVISOR_EMAIL_DAYS) {
				EmailSupervisorDaysLeft -User $_ -DaysLeft $DaysLeft
			}
		}

    }
}

SendAdminReport