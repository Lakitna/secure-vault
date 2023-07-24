Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$publicKeyXml = $Args[0];
$vaultPath = $Args[1];
$keyfilePath = $Args[2];
$allowSave = $Args[3] -eq 'true';
$saveDefault = $Args[4] -eq 'true';
if (-not $allowSave) {
    $saveDefault = $false;
}

# --------------------------

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
$vaultLocationBox.ReadOnly = $true;
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
$keyfilePathBox.ReadOnly = $true;
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

# --------------------------

# Made possible by: https://stackoverflow.com/a/76744273/2963820
function Encrypt-String($unencryptedString, $publicKeyXml) {
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $rsa.FromXmlString($publicKeyXml)

    [byte[]] $unencryptedBytes = [Text.Encoding]::UTF8.GetBytes($unencryptedString)
    $ciphertext = $rsa.Encrypt(
        $unencryptedBytes,
        [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1
    )

    $ciphertextB64 = [System.Convert]::ToBase64String($ciphertext)
    Write-Output $ciphertextB64
}

if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    $encryptedPassword = Encrypt-String $passwordBox.Text $publicKeyXml

    $json = @{
        vault=$vaultLocationBox.Text;
        keyfile=$keyfilePathBox.Text;
        password=$encryptedPassword;
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
