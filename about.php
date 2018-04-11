<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>About</title>
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
      <a class="nav-item nav-link active" href="about.php">About</a>
    </div>
  </div>
</nav>

<div class="row no-gutters">
<div class="col">
<div class="jumbotron jumbotron-fluid" style="background:#7401DF">

       <div class="container">
	     <h1 class="display-1" align="center" style="color: white;"> Info & About </h1>
       <h3 class="display-4" align="center" style="color: yellow;"> Informazioni su LigthSide </h3>
       <p align="center" style="color: white;"> Tutte le informazioni d'uso di LightSide, sul suo autore, sul perché esiste</p>
       </div>
</div>
</div>
</div>


<div class="row">
  <div class="col-md-4">
    <div class="card" style="width: 35rem;">
    <h3 class="card-title" align="center">L'Autore</h3>
    <img class="card-img-top" src="imgs/autore.jpeg" alt="author"  >
    <div class="card-body">

    <p class="card-text" align="center"><b>Chi è? Da dove viene? Dove va?</b></p>
    </div>
    <div class="card-header"><h6 align="center"> Cristiano Ceccarelli </h6></div>
    <div class="card-header">
    <p align="center"> Informatico provetto, maturando nel 2018, frequento la classe 5°AINF dell'Istituto ITTS A.Volta di Perugia.
        Tra le mie passioni ci sono la musica, in particolare rock e sperimentale, la chitarra, il cinema e le altre
        cose da intellettuale. Già autore di alcuni videogiochi e di alcuni interessanti software, sto studiando
        e spero di studiare ed apprendere ancora tante cose sul mondo dell'informatica.

    </div>
    </div>
  </div>


  <div class="col-md-4">

    <div class="col-md-4">
      <div class="card" style="width: 35rem;">
      <h3 class="card-title" align="center">Il progetto LightSide</h3>
      <img class="card-img-top" src="imgs/logotest.png" alt="author">
      <div class="card-body">

      <p class="card-text" align="center"><b>Alcune informazioni sul progetto</b></p>
      </div>
      <div class="card-header"><h6 align="center"> Cos'è? </h6></div>
      <div class="card-header">
      <p align="center"> LightSide è un malware analyzer (software di analisi di malware) che nasce come applicazione web
        pensata per permettere un rapido controllo su file e programmi di cui si vuole verificare la sicurezza.

      </div>
      <div class="card-header"><h6 align="center"> Perché esiste? </h6></div>
      <div class="card-header">
      <p align="center"> LightSide è un progetto nato per accompagnare il percorso di esame della prova orale di maturità 2018, che verterà
        su temi etici e tecnici del mondo dei malware e sugli strumenti per contrastarli.

      </div>
      <div class="card-header"><h6 align="center"> Quali tecnologie usa? </h6></div>
      <div class="card-header">
      <p align="center"> LightSide è composto di un frontend realizzato in HTML+Javascript+CSS basato su <a href="https://getbootstrap.com/">Bootstrap</a>
        e di un software scritto in PHP per l'analisi di file volta ad escludere o confermare la presenza di codice infetto nel file inviato dall'utente.
        Il software sfrutta le <a href="https://www.virustotal.com/it/documentation/public-api/">API di VirusTotal</a> e
        <a href="https://www.mysql.com/it/">MySQL</a> per il controllo sulle firme, ed altri strumenti non ancora specificati per l'analisi statica e
        dinamica di malware.

      </div>
      </div>
    </div>
  </div>

  <div class="col-md-4">
    <div class="card" style="width: 35rem;">
    <h3 class="card-title" align="center">Ringraziamenti ed extra info</h3>
    <img class="card-img-top" src="imgs/amici.jpeg" alt="author"  >
    <div class="card-body">

    <p class="card-text" align="center"><b>Tutte le cose che sono rimaste da dire, qui.</b></p>
    </div>
    <div class="card-header"><h6 align="center"> Ringraziamenti </h6></div>
    <div class="card-header">
    <p align="center"> Vorrei ringraziare la prof.ssa <a href="https://github.com/mciuchetti">Monica Ciuchetti</a> per il supporto tecnico e morale nella realizzazione
      del progetto, i miei compagni di classe e amici che vedete nella foto (a parte un intruso che fingeremo di ignorare) per il supporto
      morale durante lo sviluppo, la mia famiglia perché lo fanno tutti gli sviluppatori di software e suona bene, il sig. Nicolò Vescera per l'aiuto
      nel capire come andrebbe fatta una buona tesina, e infine me stesso.

    </div>

    <div class="card-header"><h6 align="center"><a href="https://github.com/crilose/LightSide"> GitHub Repository </a></h6></div>
    </div>

  </div>
</div>


<div class="row">
</div>
</div>

</body>
</html>
