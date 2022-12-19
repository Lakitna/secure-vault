Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$vaultPath = $Args[0];
$keyfilePath = $Args[1]
$allowSave = $Args[2] -eq 'true';
$saveDefault = $Args[3] -eq 'true';
if (-not $allowSave) {
    $saveDefault = $false;
}


$form = New-Object System.Windows.Forms.Form
$form.Size = New-Object System.Drawing.Size(320,240)
$form.StartPosition = 'CenterScreen'
$form.MaximizeBox = $false;
$form.MinimizeBox = $false;
$form.FormBorderStyle = 3; # FixedDialog (make non-resizable)
$form.Text = 'Enter password'


$label = New-Object System.Windows.Forms.Label
$label.Location = New-Object System.Drawing.Point(15,10)
$label.Size = New-Object System.Drawing.Size(270,15)
$label.Text = 'KeePass vault path'
$form.Controls.Add($label)

$vaultLocationBox = New-Object System.Windows.Forms.TextBox
$vaultLocationBox.Text = $vaultPath
$vaultLocationBox.Location = New-Object System.Drawing.Point(15,25)
$vaultLocationBox.Size = New-Object System.Drawing.Size(275,30)
$vaultLocationBox.BackColor = "LightGray"
$form.Controls.Add($vaultLocationBox)


$label = New-Object System.Windows.Forms.Label
$label.Location = New-Object System.Drawing.Point(15,50)
$label.Size = New-Object System.Drawing.Size(275,15)
$label.Text = 'KeePass keyfile path'
$form.Controls.Add($label)

$keyfilePathBox = New-Object System.Windows.Forms.TextBox
$keyfilePathBox.Text = $keyfilePath
$keyfilePathBox.Location = New-Object System.Drawing.Point(15,65)
$keyfilePathBox.Size = New-Object System.Drawing.Size(275,30)
$keyfilePathBox.BackColor = "LightGray"
$form.Controls.Add($keyfilePathBox)


$label = New-Object System.Windows.Forms.Label
$label.Location = New-Object System.Drawing.Point(15,90)
$label.Size = New-Object System.Drawing.Size(275,15)
$label.Text = 'KeePass vault password'
$form.Controls.Add($label)

$passwordBox = New-Object System.Windows.Forms.TextBox
$passwordBox.PasswordChar = '*'
$passwordBox.Location = New-Object System.Drawing.Point(15,105)
$passwordBox.Size = New-Object System.Drawing.Size(275,30)
$form.Controls.Add($passwordBox)


$checkBox = New-Object System.Windows.Forms.CheckBox
$checkBox.Location = New-Object System.Drawing.Point(15,130)
$checkBox.Size = New-Object System.Drawing.Size(285,30)
$checkBox.Text = 'Remember password in the OS credential manager'
$checkBox.Visible = $allowSave;
$checkBox.Checked = $saveDefault;
$form.Controls.Add($checkBox)


$okButton = New-Object System.Windows.Forms.Button
$okButton.Location = New-Object System.Drawing.Point(75,165)
$okButton.Size = New-Object System.Drawing.Size(75,23)
$okButton.Text = 'OK'
$okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.AcceptButton = $okButton
$form.Controls.Add($okButton)

$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Location = New-Object System.Drawing.Point(150,165)
$cancelButton.Size = New-Object System.Drawing.Size(75,23)
$cancelButton.Text = 'Cancel'
$cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.CancelButton = $cancelButton
$form.Controls.Add($cancelButton)


$passwordBox.Select();
$form.Topmost = $true
$result = $form.ShowDialog()


if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    $password = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($passwordBox.Text))

    $json = @{
        vault=$vaultLocationBox.Text;
        keyfile=$keyfilePathBox.Text;
        password=$password;
        save=$checkBox.Checked
    } | ConvertTo-Json -Compress
    Write-Output $json
}
else {
    $json = @{
        cancel=$true;
    } | ConvertTo-Json -Compress
    Write-Output $json
}
