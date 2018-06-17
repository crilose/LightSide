<?php

function validHash($md5)
{
    return preg_match('/^[a-f0-9]{32}$/', $md5);
}

function validSha($sha)
{
  return preg_match('/^[a-f0-9]{64}$/', $sha);
}









 ?>
