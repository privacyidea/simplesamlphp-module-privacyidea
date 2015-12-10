<?php
// First of all we determine how we were called
$chal_resp_attributes = NULL;
$chal_resp_message = '';
$hideResponseInput = FALSE;
$u2fSignRequest = NULL;
$password_text = $this->t('{privacyidea:privacyidea:password_otp}');

if ($this->data['errorcode'] === "CHALLENGERESPONSE") {
        $password_text = $this->t('{privacyidea:privacyidea:otp}');
        SimpleSAML_Logger::debug("Attributes: ". print_r($this->data["chal_resp_attributes"], TRUE));
        $chal_resp_attributes = $this->data['chal_resp_attributes'];
        $hideResponseInput = $chal_resp_attributes->hideResponseInput;
        $chal_resp_message = $this->data['chal_resp_message'];
        // check if this is U2F
        $u2fSignRequest = $chal_resp_attributes->u2fSignRequest;
        SimpleSAML_Logger::debug("u2fSignRequest: ". print_r($u2fSignRequest, TRUE));
}

if ($u2fSignRequest) {
	// Add javascript for U2F support before including the header.
	$this->data['head'] = '<script type="text/javascript" src="'.SimpleSAML_Module::getModuleUrl('privacyidea/js/u2f-api.js').'"></script>\n';
	$this->data['head'] .= '<script type="text/javascript" src="'.SimpleSAML_Module::getModuleUrl('privacyidea/js/u2f.js').'"></script>';
}

$this->data['header'] = $this->t('{privacyidea:privacyidea:header}');
if (strlen($this->data['username']) > 0) {
        $this->data['autofocus'] = 'password';
} else {
        $this->data['autofocus'] = 'username';
}
$this->includeAtTemplateBase('includes/header.php');

?>


<?php
if ($this->data['errorcode'] !== NULL) {
        if ($this->data['errorcode'] !== "CHALLENGERESPONSE") {
?>


	<div style="border-left: 1px solid #e8e8e8; border-bottom: 1px solid #e8e8e8; background: #f5f5f5">
		<img src="/<?php echo $this->data['baseurlpath']; ?>resources/icons/experience/gtk-dialog-error.48x48.png" class="float-l erroricon" style="margin: 15px " />
		<h2><?php echo $this->t('{login:error_header}'); ?></h2>
		<p><b><?php echo htmlspecialchars($this->t('{errors:title_' . $this->data['errorcode'] . '}', $this->data['errorparams'])); ?></b></p>
		<p><?php echo htmlspecialchars($this->t('{errors:descr_' . $this->data['errorcode'] . '}', $this->data['errorparams'])); ?></p>
	</div>
<?php
	} // End of CHALLENGERESPONSE
}  // end of errorcode
?>


<div class="container">
<div class="login">
<div class="loginlogo"></div>
<?php
if ($this->data['errorcode'] === "CHALLENGERESPONSE") {
	echo '<h2 style="break: both">' .$this->t('{privacyidea:privacyidea:login_title_challenge}') . '</h2>';
	echo '<p class="logintext">' . $this->t('{privacyidea:privacyidea:login_text_challenge}') . '</p>';
} else {
	echo '<h2 style="break: both">' . $this->t('{privacyidea:privacyidea:login_title}') . '</h2>';
	echo '<p class="logintext">' . $this->t('{privacyidea:privacyidea:login_text}') . '</p>';
} // end of !CHALLENGERESPONSE
?>
	<form action="?" method="post" id="piLoginForm"  name="piLoginForm" class="loginform">
	<table>
		<tr>
			<td>
<?php
if ($this->data['forceUsername']) {
	echo '<strong style="font-size: medium">' . htmlspecialchars($this->data['username']) . '</strong>';
	echo '<input type="hidden" id="username" name="username" value="' . htmlspecialchars($this->data['username']) . '" />';
	echo '<input type="hidden" id="transaction_id" name="transaction_id" value="'. $this->data['transaction_id']. '" />';
	echo '<input type="hidden" id="clientData" name="clientData" value="" />';
	echo '<input type="hidden" id="signatureData" name="signatureData" value="" />';
} else {
	echo '<label for="username">';
	echo '<input type="text" id="username" tabindex="1" name="username" value="' . htmlspecialchars($this->data['username']) . '"';
	echo ' placeholder="'. $this->t('{login:username}') .'" />';
	echo '</label>';
}
?>
			</td>
<?php
if ($this->data['rememberUsernameEnabled'] || $this->data['rememberMeEnabled']) {
	$rowspan = 1;
} elseif (array_key_exists('organizations', $this->data)) {
	$rowspan = 3;
} else {
	$rowspan = 2;
}
?>
			<td style="padding: .4em;" rowspan="<?php echo $rowspan; ?>">
<?php
if ($this->data['rememberUsernameEnabled'] || $this->data['rememberMeEnabled']) {
    if ($this->data['rememberUsernameEnabled']) {
        echo str_repeat("\t", 4);
        echo '<input type="checkbox" id="remember_username" tabindex="4" name="remember_username" value="Yes" ';
        echo ($this->data['rememberUsernameChecked'] ? 'checked="Yes" /> ' : '/> ');
        echo $this->t('{login:remember_username}');
    }
    if ($this->data['rememberMeEnabled']) {
        echo str_repeat("\t", 4);
        echo '<input type="checkbox" id="remember_me" tabindex="4" name="remember_me" value="Yes" ';
        echo $this->data['rememberMeChecked'] ? 'checked="Yes" /> ' : '/> ';
        echo $this->t('{login:remember_me}');
    }
} else {
	$text = $this->t('{login:login_button}');
	echo str_repeat("\t", 4);
	if ($u2fSignRequest === NULL) {
		echo "<input type=\"submit\" tabindex=\"4\" id=\"regularsubmit\" value=\"{$text}\" />";
	}
}
?>
			</td>
		</tr>
		<tr>
<!-------------  
In case of challenge response with the U2F, we hide the password.
---------------->
<?php
	if ($hideResponseInput) {
		echo '<td style="padding: .3em;" colspan="2">' . $chal_resp_message . '</td>';
	} else {
		echo '<td><label for="password">';
		echo '<input id="password" type="password" tabindex="2" name="password" placeholder="'. $password_text . '" />';
		echo '</label></td>';
	}
?>

<?php
// Move submit button to next row if remember checkbox enabled
if ($this->data['rememberUsernameEnabled'] || $this->data['rememberMeEnabled']) {
	$rowspan = (array_key_exists('organizations', $this->data) ? 2 : 1);
	SimpleSAML_Logger::debug("u2fSignRequest: " . print_r($u2fSignRequest, TRUE));
	if ($u2fSignRequest === NULL) {
		echo '<td style="padding: .4em;" rowspan="' . $rowspan . '">';
		echo '<input type="submit" tabindex="5" id="regularsubmit" value="'. $this->t('{login:login_button}'). '" />';
		echo '</td>';
	}
}
?>
		</tr>

<?php
if (array_key_exists('organizations', $this->data)) {
?>
		<tr>
			<td style="padding: .3em;"><?php echo $this->t('{login:organization}'); ?></td>
			<td><select name="organization" tabindex="3">
<?php
if (array_key_exists('selectedOrg', $this->data)) {
	$selectedOrg = $this->data['selectedOrg'];
} else {
	$selectedOrg = NULL;
}

foreach ($this->data['organizations'] as $orgId => $orgDesc) {
	if (is_array($orgDesc)) {
		$orgDesc = $this->t($orgDesc);
	}

	if ($orgId === $selectedOrg) {
		$selected = 'selected="selected" ';
	} else {
		$selected = '';
	}

	echo '<option ' . $selected . 'value="' . htmlspecialchars($orgId) . '">' . htmlspecialchars($orgDesc) . '</option>';
}
?>
			</select></td>
		</tr>
<?php
}
?>
	<tr><td></td><td>
	<!-- TODO: when is this called. On a mobile device. Why so complicated? -->
	<!-- <input type="submit" tabindex="5" id="mobilesubmit" value="<?php echo $this->t('{login:login_button}'); ?>" />-->
	</td></tr>
	</table>
</div>  <!-- End of login -->
</div>  <!-- End of container -->
<?php
foreach ($this->data['stateparams'] as $name => $value) {
	echo('<input type="hidden" name="' . htmlspecialchars($name) . '" value="' . htmlspecialchars($value) . '" />');
}
?>

	</form>

<?php

if(!empty($this->data['links'])) {
	echo '<ul class="links" style="margin-top: 2em">';
	foreach($this->data['links'] AS $l) {
		echo '<li><a href="' . htmlspecialchars($l['href']) . '">' . htmlspecialchars($this->t($l['text'])) . '</a></li>';
	}
	echo '</ul>';
}

$this->includeAtTemplateBase('includes/footer.php');

if ($u2fSignRequest) {
	// We call the U2F signing function
	SimpleSAML_Logger::debug("Calling Javascript with u2fSignRequest: ". print_r($u2fSignRequest, TRUE));
	echo '<script type="text/javascript">';
	echo 'sign_u2f_request(';
	echo '"'.$u2fSignRequest->challenge.'",';
	echo '"'.$u2fSignRequest->keyHandle.'",';
	echo '"'.$u2fSignRequest->appId.'");';
	echo '</script>';
}
?>
