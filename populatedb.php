<?php
error_reporting(0);

require_once 'connect.php';
require_once 'utils.php';
$hash;
$nome;
$sha;
?>

<html>
<head>
  <meta charset="utf-8">
  <title>Aggiungi Malware al Database</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="/style/bootstrap.css">
  <link rel="stylesheet" type="text/css" href="style.css">
  <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.12.9/umd/popper.min.js"></script>
  <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.min.js"></script>
  <script src="scripts/inputbtn.js"></script>

</head>
<body style="overflow-x: hidden;">

  <div class="container-fluid">
  <nav class="navbar navbar-expand-lg navbar-dark" style="background-color: #2C2929;">
  <img src="imgs/logotest.png" width="50" height="50" class="d-inline-block align-top" alt="logo">
  <a class="navbar-brand" style="color: white">LightSide</a>
  <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNavAltMarkup" aria-controls="navbarNavAltMarkup" aria-expanded="false" aria-label="Toggle navigation">
    <span class="navbar-toggler-icon"></span>
  </button>
  <div class="collapse navbar-collapse" id="navbarNavAltMarkup">
    <div class="navbar-nav">
      <a class="nav-item nav-link" href="index.html">Homepage <span class="sr-only">(current)</span></a>
      <a class="nav-item nav-link active" href="populatedb.php">Aggiungi Malware</a>
      <a class="nav-item nav-link" href="about.php">About</a>
    </div>
  </div>
  </nav>

  <div class="row no-gutters">
  <div class="col">
  <div class="jumbotron jumbotron-fluid" style="background:#7401DF">

         <div class="container">
  	     <h1 class="display-1" align="center" style="color: white;"> Definisci Malware </h1>
         <h3 class="display-4" align="center" style="color: yellow;"> Aggiungi un malware al database </h3>
         <p align="center" style="color: white;"> Tramite il form potrai inserire una nuova definizione di malware al database, specificando nome del malware e due tipi di hash</p>
         </div>
  </div>
  </div>
  </div>

  <div class="row">
    <div class="col-md-4">
    </div>
    <div class="col-md-4">
      <form action="" method="post">
        <div class="form-group">
        <div class="input-group mb-3">
          <div class="input-group-prepend">
            <span class="input-group-text" id="inputGroup-sizing-default">Nome del malware</span>
          </div>
          <input type="text" name="nome" class="form-control" aria-label="Default" aria-describedby="inputGroup-sizing-default" required>
        </div>

        <div class="input-group mb-3">
          <div class="input-group-prepend">
            <span class="input-group-text" id="inputGroup-sizing-default">Hash MD5</span>
          </div>
          <input type="text" name="hash" class="form-control" aria-label="Default" pattern=".{32}" aria-describedby="inputGroup-sizing-default" required>
        </div>

        <div class="input-group mb-3">
          <div class="input-group-prepend">
            <span class="input-group-text" id="inputGroup-sizing-default">Hash SHA-256</span>
          </div>
          <input type="text" name="sha" class="form-control" aria-label="Default" pattern=".{64}" aria-describedby="inputGroup-sizing-default" required> <span class="input-group-btn">
                <button type="submit" class="btn btn-primary pull-right">Invia</button>
            </span>
        </div>

    	</div>
      </form>
    </div>

    <div class="col-md-4">
    </div>
  </div>
</div>
<div class="footer-copyright py-3 text-center">
        2018, LightSide, Realizzato da <a href="https://github.com/crilose">Cristiano Ceccarelli</a>
</div>

</body>
</html>



<?php

$hashtoinsert = $_POST['hash'];
$shatoinsert = $_POST['sha'];
$nome = $_POST['nome'];

if(validHash($hashtoinsert) && validSha($shatoinsert))
{
  $sql = $database->prepare("INSERT INTO hashes(nome_malware, hash_malware, sha256, data_inserito) VALUES (?,?,?,CURRENT_TIMESTAMP)");
  $sql->execute(array($nome, $hashtoinsert, $shatoinsert));
}




 ?>
