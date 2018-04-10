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


      /*if(in_array($file_ext,$expensions)=== false){
         $errors[]="Estensione non valida. Inserisci un eseguibile o file infettabile.";
      }*/



      if(empty($errors)==true) {
         move_uploaded_file($file_tmp,"uploads/".$file_name);
         //echo "File correttamente caricato";
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
  <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
  <link rel="stylesheet" type="text/css" href="style.css">
  <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.12.9/umd/popper.min.js"></script>
  <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.min.js"></script>
  <script src="scripts/inputbtn.js"></script>

</head>
<body>


  <nav class="navbar navbar-expand-lg navbar-light" style="background-color: #8EA4AF;">
  <img src="imgs/logotest.png" width="50" height="50" class="d-inline-block align-top" alt="logo">
  <a class="navbar-brand">LightSide</a>
  <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNavAltMarkup" aria-controls="navbarNavAltMarkup" aria-expanded="false" aria-label="Toggle navigation">
    <span class="navbar-toggler-icon"></span>
  </button>
  <div class="collapse navbar-collapse" id="navbarNavAltMarkup">
    <div class="navbar-nav">
      <a class="nav-item nav-link active" href="index.html">Homepage <span class="sr-only">(current)</span></a>
      <a class="nav-item nav-link" href="populatedb.php">Aggiungi Malware</a>
      <a class="nav-item nav-link" href="about.php">About</a>
    </div>
  </div>
</nav>

<div class="row">
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

<div class="row" id="sendfile">
  <div class="col-sm-3">

  <div class="card" style="width: 25rem;border:5px solid black;  border-radius: 25px;">
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

  <div class="col-sm-3">

    <div class="card" style="width: 25rem;border:5px solid black;  border-radius: 25px;">
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
  <div class="col-sm-3">

    <div class="card" style="width: 25rem;border:5px solid black;  border-radius: 25px;">
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


<div class="row">
</div>
</div>
<?php
unlink("uploads/".$file_name); //elimino il file dopo l'analisi


?>
</body>
</html>
