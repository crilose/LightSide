<?php

$total = 100;
$safe = 0;
$unsafe = 0;
$msg = "Il file non è sicuro! Scappa!";


//Funzione di controllo dell'hash
function hashCheck($filename)
{
  global $safe, $unsafe;
  $col = 'mysql:host=localhost;dbname=malwarescan';
  $user = "root";
  $pass = "";
  $database = new PDO($col ,$user,$pass);


  $inputhash = hash_file('md5', "uploads/".$filename);
  $sql = $database->prepare("SELECT nome_malware FROM hashes WHERE hash_malware = '$inputhash'");
  $sql->execute();
  if($r = $sql->fetch(PDO::FETCH_ASSOC))
  {
    $nomemalware = $r['nome_malware'];
    echo '<li class="list-group-item" style="background-color: red; color: white;">Positivo, Rilevato malware: ' . $nomemalware . ' <img src="imgs/notok.png" height="40"></li>';
    $unsafe = $unsafe + 5;
    return true;
  }
  else {
    echo '<li class="list-group-item" style="background-color: green; color: white;">Negativo, File pulito.<img src="imgs/ok.png" height="40"></li>';
    $safe = $safe + 5;
    return false;
  }
}
//Funzione di controllo dello sha256
function shaCheck($filename)
{
  global $safe, $unsafe;
  $col = 'mysql:host=localhost;dbname=malwarescan';
  $user = "root";
  $pass = "";
  $database = new PDO($col ,$user,$pass);


  $inputhash = hash_file('sha256', "uploads/".$filename);
  $sql = $database->prepare("SELECT nome_malware FROM hashes WHERE sha256 = '$inputhash'");
  $sql->execute();
  if($r = $sql->fetch(PDO::FETCH_ASSOC))
  {
    $nomemalware = $r['nome_malware'];
    echo '<li class="list-group-item" style="background-color: red; color: white;">Positivo, Rilevato malware: ' . $nomemalware . ' <img src="imgs/notok.png" height="40"></li>';
    $unsafe = $unsafe + 5;
    return true;
  }
  else {
    echo '<li class="list-group-item" style="background-color: green; color: white;">Negativo, File pulito.<img src="imgs/ok.png" height="40"></li>';
    $safe = $safe + 5;
    return false;
  }
}

function virusTotalSend($filepath,$filehash)
{
  global $safe, $unsafe;
  $virustotal_api_key = '926d4d760ed7c7fcb5b70f8f35907b580a3f06a40889ad678c7683033628ace6'; //SENSIBILE: qui inseriamo la nostra api-key
  $file_name_with_full_path = realpath('/uploads/'.$filepath); //Formiamo il percorso del file
  $cfile = curl_file_create($file_name_with_full_path); //Creiamo un file da inviare mediante curl
  $report_url = 'https://www.virustotal.com/vtapi/v2/file/report?apikey='.$virustotal_api_key."&resource=".$filehash; //Il link a cui inviare i dati

  $api_reply = file_get_contents($report_url); //otteniamo il risultato
  $api_reply_array = json_decode($api_reply, true); //decodifichiamo la risposta json

//Se il codice è -2, cioè richiesta in coda, visualizziamo un messaggio
  if($api_reply_array['response_code']==-2){
    echo '<div class="card-header"><h6 align="center"> Il file è in coda per essere analizzato.. riprova più tardi. </h6></div>';
    echo '<div class="card-header"><div align="center"><img src="imgs/sadface.png" height="40"></div></div>';
}

// Se otteniamo risposta positiva
if($api_reply_array['response_code']==1){
  echo '<div class="card-header"><h6> Numero positivi </h6></div>';
  if($api_reply_array['positives']>0)
  {
    echo '<li class="list-group-item" style="background-color: red; color: white">'.$api_reply_array['positives']. '</li>';
    $unsafe = $unsafe + 30;
  }
  else {
    echo '<li class="list-group-item" style="background-color: green; color: white">'.$api_reply_array['positives']. '</li>';
    $safe = $safe + 30;
  }
  echo '<div class="card-header"><h6> Numero antivirus </h6></div>';
  echo '<li class="list-group-item">'.$api_reply_array['total']. '</li>';
  echo '<div class="card-header"><h6> Timestamp ultima scansione </h6></div>';
  echo '<li class="list-group-item">'.$api_reply_array['scan_date']. '</li>';
	//print_r($api_reply_array);
}

if($api_reply_array['response_code']==0)
{
  echo '<div class="card-header"><h6 align="center"> Il file non ha scansioni nel database di VirusTotal </h6></div>';
  echo '<div class="card-header"><div align="center"><img src="imgs/sadface.png" height="40"></div></div>';
}
}

//Funzione per ottenere solo l'hash del file
function getHash($filename)
{
  $hash = hash_file('sha256', "uploads/".$filename);
  return $hash;
}

function webCallAnalysis($filename)
{
global $safe, $unsafe;
  //Il contenuto del file dentro la variabile
  $filecontent = file_get_contents("uploads/".$filename);
  //Cerchiamo tutti i match di url validi
  preg_match_all('/(http|https)\:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3}/', $filecontent, $urls);
  $riskyurl = 0; //rischio iniziale per url zero
  //Controlliamo gli url
  for($i=0;$i<count($urls[0]);$i++)
  {
    $api_key = '926d4d760ed7c7fcb5b70f8f35907b580a3f06a40889ad678c7683033628ace6';
    $report_url = "https://www.virustotal.com/vtapi/v2/url/report?apikey=$api_key&resource=" .$urls[0][$i];
    $api_reply = file_get_contents($report_url); //otteniamo il risultato
    $api_reply_array = json_decode($api_reply, true); //decodifichiamo la risposta json
    if($api_reply_array['response_code']==1)
    {
      if($api_reply_array['positives']>0)
      {
        $riskyurl = 1; //almeno un link è sospetto
      }
    }
  }

  $numlinks = substr_count($filecontent, 'http://') + substr_count($filecontent, "https://"); //contiamo il numero di link

  if($numlinks>0) //se è maggiore di zero
    {
      $unsafe = $unsafe + 5;
      if($riskyurl == 1)
      {
        echo '<li class="list-group-item" style="background-color: red; color: white">'.$numlinks . '<span class="badge badge-danger">Almeno 1 URL sospetto!</span>'; //barra rossa
        $unsafe = $unsafe + 20;
      }
      else {
        echo '<li class="list-group-item" style="background-color: orange; color: white">'.$numlinks . '<span class="badge badge-warning">Non ci sono URL sospetti!</span>'; //barra rossa
        $safe = $safe + 10;
      }

      echo '<div class="dropdown" style="position: absolute; right:3px; top:5px;">
      <button class="btn btn-secondary dropdown-toggle" type="button" id="dropdownMenuButton" data-toggle="dropdown" aria-haspopup="true" aria-expanded="true">
        Visualizza URL
      </button>
      <div class="dropdown-menu" aria-labelledby="dropdownMenuButton">';
      //Elenco dei link trovati
      for($i=0;$i<count($urls[0]);$i++)
      {
        echo '<a class="dropdown-item">'. $urls[0][$i].'</a>';
      }
      echo'</div> </div></li>';
    }
    else {
      echo '<li class="list-group-item" style="background-color: green; color: white">'.$numlinks . '</li>'; //barra verde
      $safe = $safe + 10;

    }

}

function ipAnalysis($filename)
{
  global $safe, $unsafe;
  //Il contenuto del file dentro la variabile
  $filecontent = file_get_contents("uploads/".$filename);
    //Cerchiamo tutti i match di ip validi
  preg_match_all('/([0-9]{1,3}\.){3}[0-9]{1,3}/', $filecontent, $ips);
  $riskyip = 0; //rischio iniziale per url zero

  //controlliamo gli ip
  for($i=0;$i<count($ips[0]);$i++)
  {
    $api_key = '926d4d760ed7c7fcb5b70f8f35907b580a3f06a40889ad678c7683033628ace6';
    $report_url = "https://www.virustotal.com/vtapi/v2/url/report?apikey=$api_key&resource=" .$ips[0][$i];
    $api_reply = file_get_contents($report_url); //otteniamo il risultato
    $api_reply_array = json_decode($api_reply, true); //decodifichiamo la risposta json
    if($api_reply_array['response_code']==1)
    {
      if($api_reply_array['positives']>0)
      {
        $riskyip = 1; //almeno un link è sospetto
      }
    }
  }
  $numips = $i; //contiamo gli ip

  if($numips>0) //se è maggiore di zero
    {
      $unsafe = $unsafe + 5;
      if($riskyip == 1)
      {
        echo '<li class="list-group-item" style="background-color: red; color: white">'.$numips . '<span class="badge badge-danger">Almeno 1 IP sospetto!</span>'; //barra rossa
        $unsafe = $unsafe + 20;
      }
      else {
        echo '<li class="list-group-item" style="background-color: orange; color: white">'.$numips . '<span class="badge badge-warning">Non ci sono IP sospetti!</span>'; //barra rossa
        $safe = $safe + 10;
      }

      echo '<div class="dropdown" style="position: absolute; right:3px; top:5px;">
      <button class="btn btn-secondary dropdown-toggle" type="button" id="dropdownMenuButton" data-toggle="dropdown" aria-haspopup="true" aria-expanded="true">
        Visualizza indirizzi IP
      </button>
      <div class="dropdown-menu" aria-labelledby="dropdownMenuButton">';
      //Elenco dei link trovati
      for($i=0;$i<count($ips[0]);$i++)
      {
        echo '<a class="dropdown-item">'. $ips[0][$i].'</a>';
      }
      echo'</div> </div></li>';
    }
    else {
      echo '<li class="list-group-item" style="background-color: green; color: white">'.$numips . '</li>'; //barra verde
      $safe = $safe + 10;
    }
}


function finalSafety()
{
  global $safe, $unsafe,$msg;
  echo '<div class="col-sm-3">';
  determineMsg();
  if($safe > $unsafe)
  {
    echo '<div class="card border-dark mb-3" style="width: 25rem; background-color: #7401DF;">
    <h3 class="card-title" align="center" style="color:white">Resoconto delle analisi</h3>
    <img class="card-img-top" src="imgs/safe.png" alt="web" height="350" >
    <div class="card-body">';
  }
  else {
    echo '<div class="card border-dark mb-3" style="width: 25rem; background-color: #7401DF;">
    <h3 class="card-title" align="center" style="color:white">Resoconto delle analisi</h3>
    <img class="card-img-top" src="imgs/unsafe.png" alt="web" height="350" >
    <div class="card-body">';
  }
  echo '<p class="card-text" align="center" style="color:white">Il report finale sul tuo file.</p>
  </div>
  <div class="card-header"><h6 style="color:white"> Punteggio sicurezza </h6></div>
  <li class="list-group-item" style="background-color: green; color: white">'.$safe . '</li>
  <div class="card-header"><h6 style="color:white"> Punteggio pericolo </h6></div>
  <li class="list-group-item" style="background-color: red; color: white">'.$unsafe . '</li>
  <div class="card-header"><h6 style="color:white"> Il verdetto </h6></div>
  <li class="list-group-item" style="background-color: black; color: white">'.$msg . '</li>
  </div>
</div>';


}


function determineMsg()
{
  global $safe, $unsafe,$msg;
  switch($num = $safe - $unsafe)
  {
    case $num==0:
    $msg = "Il file è incerto!";
    break;

    case ($num<=10):
      $msg = "Il file è probabilmente sicuro, ma tienilo d'occhio!";
      break;

    case ($num<=20&&$num>10):
      $msg = "Il file è quasi sicuramente innocuo!";
      break;

  }

}





















 ?>
