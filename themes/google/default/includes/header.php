<?php


/**
 * Support the htmlinject hook, which allows modules to change header, pre and post body on all pages.
 */
$this->data['htmlinject'] = array(
    'htmlContentPre' => array(),
    'htmlContentPost' => array(),
    'htmlContentHead' => array(),
);


$jquery = array();
if (array_key_exists('jquery', $this->data)) $jquery = $this->data['jquery'];

if (array_key_exists('pageid', $this->data)) {
    $hookinfo = array(
        'pre' => &$this->data['htmlinject']['htmlContentPre'],
        'post' => &$this->data['htmlinject']['htmlContentPost'],
        'head' => &$this->data['htmlinject']['htmlContentHead'],
        'jquery' => &$jquery,
        'page' => $this->data['pageid']
    );

    SimpleSAML_Module::callHooks('htmlinject', $hookinfo);
}

// - o - o - o - o - o - o - o - o - o - o - o - o -

/**
 * Do not allow to frame simpleSAMLphp pages from another location.
 * This prevents clickjacking attacks in modern browsers.
 *
 * If you don't want any framing at all you can even change this to
 * 'DENY', or comment it out if you actually want to allow foreign
 * sites to put simpleSAMLphp in a frame. The latter is however
 * probably not a good security practice.
 */
header('X-Frame-Options: SAMEORIGIN');

?><!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
    <meta http-equiv="X-UA-Compatible" content="IE=edge"/>
    <meta name="viewport"
          content="target-densitydpi=device-dpi, width=device-width, height=device-height, initial-scale=1.0"/>
    <title>
        <?php echo($this->t('{privacyidea:google:pagetitle}')); ?>
    </title>

    <link rel="icon" type="image/icon" href="/favicon.ico"/>

    <?php
    if ($this->isLanguageRTL()) {
        ?>
        <link rel="stylesheet" type="text/css"
              href="/<?php echo $this->data['baseurlpath']; ?>resources/default-rtl.css"/>
        <?php
    }
    ?>
    <meta name="robots" content="noindex, nofollow"/>
    <?php
    if (array_key_exists('head', $this->data)) {
        echo '<!-- head -->' . $this->data['head'] . '<!-- /head -->';
    }
    ?>

    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="/css/google.css">

</head>
<body>
<div id="wrap">
    <div class="container">
        <div id="title">
            <h1><?php echo($this->t('{privacyidea:google:pageheader}')); ?></h1>
        </div>
        <div class="main-content">
            <div class="card signin-card">
                <div class="circle-mask">
                    <canvas id="canvas" class="circle" width="96" height="96"></canvas>
                </div>
