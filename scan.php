<?php

require_once 'connect.php';
require_once 'scanning.php';

if(isset($_FILES['InputFile'])){
      $errors= array();
      $file_name = $_FILES['InputFile']['name'];
      $file_size = $_FILES['InputFile']['size'];
      $file_tmp = $_FILES['InputFile']['tmp_name'];
      $file_type = $_FILES['InputFile']['type'];
      $tmp = explode('.',$_FILES['InputFile']['name']);
      $file_ext=strtolower(end($tmp));

      $expensions= array("jpeg","jpg","png","exe","jar","vbs","dll","txt");
      echo $_FILES['InputFile']['error'];

      /*if(in_array($file_ext,$expensions)=== false){
         $errors[]="Estensione non valida. Inserisci un eseguibile o file infettabile.";
      }*/



      if(empty($errors)==true) {
         if(move_uploaded_file($file_tmp,"uploads/".$file_name)==true)
         {
           echo "File correttamente caricato: " . "uploads/".$file_name;
         }
         else {
           echo "Problemi in vista";
         }

      }else{
         print_r($errors);
      }
   }

?>

<html>
<head>
  <meta charset="utf-8">
  <title>Report dell'Analisi</title>
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
      <a class="nav-item nav-link" href="populatedb.php">Aggiungi Malware</a>
      <a class="nav-item nav-link" href="about.php">About</a>
    </div>
  </div>
</nav>

<div class="row no-gutters">
<div class="col">
<div class="jumbotron jumbotron-fluid" style="background:#7401DF !important">

       <div class="container">
	     <h1 class="display-1" align="center" style="color: white;"> Report di Analisi </h1>
       <h3 class="display-4" align="center" style="color: yellow;"> Ecco i risultati! </h3>
       <p align="center" style="color: white;"> L'analisi effettuata dal sito ha puramente scopo didattico e non è interpretabile come conferma della pericolosità o meno del file!</p>
       </div>
</div>
</div>
</div>

<div class="row">
  <div class="col-sm">

  <div class="card border-dark mb-3" style="width: 25rem;">
  <h3 class="card-title" align="center">Identikit</h3>
  <img class="card-img-top" src="imgs/guy.png" alt="guy" height="300" >
  <div class="card-body">

  <p class="card-text" align="center">Alcune informazioni di base sul file che hai caricato ed analizzato.</p>
  </div>
  <div class="card-header"><h6> Nome del file </h6></div>
  <li class="list-group-item"><?php echo $file_name ?></li>
  <div class="card-header"><h6> Tipo di file </h6></div>
  <li class="list-group-item"><?php echo $file_type ?></li>
  <div class="card-header"><h6> Hash MD5 </h6></div>
  <li class="list-group-item"><?php echo getHash($file_name) ?></li>
  <div class="card-header"><h6> Dimensioni </h6></div>
  <li class="list-group-item"><?php echo $file_size/1024/1024 . " MB" ?></li>


  </div>

</div>

  <div class="col-sm">

    <div class="card border-dark mb-3" style="width: 25rem;">
    <h3 class="card-title" align="center">Firma Locale</h3>
    <img class="card-img-top" src="imgs/localdb.png" alt="guy" height="300" >
    <div class="card-body">

    <p class="card-text" align="center">I risultati del controllo di firma su database locale.</p>
    </div>
    <div class="card-header"><h6> Controllo MD5 </h6></div>
    <?php hashCheck($file_name); //facciamo un controllo sull'hash nel nostro Database ?>
    <div class="card-header"><h6>Controllo SHA-256 </h6> </div>
    <?php shaCheck($file_name); //facciamo un controllo sullo sha-256 nel nostro Database ?>
    </div>



  </div>
  <div class="col-sm">

    <div class="card border-dark mb-3" style="width: 25rem;">
    <h3 class="card-title" align="center">Firma VirusTotal</h3>
    <img class="card-img-top" src="imgs/vtotal.png" alt="guy" height="300" >
    <div class="card-body">

    <p class="card-text" align="center">I risultati del controllo di firma sul database di VirusTotal.</p>
    </div>
    <?php
      virusTotalSend($file_name,getHash($file_name)); //facciamo un controllo sul database di virustotal
     ?>

  </div>

</div>

<div class="col-sm">

  <div class="card border-dark mb-3" style="width: 25rem;">
  <h3 class="card-title" align="center">Comunicazioni in Rete</h3>
  <img class="card-img-top" src="imgs/web.png" alt="web" height="350" >
  <div class="card-body">

  <p class="card-text" align="center">I risultati del controllo sulle comunicazioni in rete del file.</p>
  </div>
  <div class="card-header"><h6> URL Rilevati </h6></div>
  <?php webCallAnalysis($file_name); //facciamo un controllo sull'hash nel nostro Database ?>
  <div class="card-header"><h6> IP Rilevati </h6></div>
  <?php ipAnalysis($file_name); //facciamo un controllo sull'hash nel nostro Database ?>
  </div>
</div>

</div>

<div class="row">

  <?php finalSafety(); ?>
</div>



<?php
unlink('uploads/'.$file_name) //elimino il file dopo l'analisi
 ?>


</div>
<div class="footer-copyright py-3 text-center">
        2018, LightSide, Realizzato da <a href="https://github.com/crilose">Cristiano Ceccarelli</a>
</div>
</body>
</html>
