<?php

//Funzione di controllo dell'hash
function hashCheck($filename)
{
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
    return true;
  }
  else {
    echo '<li class="list-group-item" style="background-color: green; color: white;">Negativo, File pulito.<img src="imgs/ok.png" height="40"></li>';
    return false;
  }
}
//Funzione di controllo dello sha256
function shaCheck($filename)
{
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
    return true;
  }
  else {
    echo '<li class="list-group-item" style="background-color: green; color: white;">Negativo, File pulito.<img src="imgs/ok.png" height="40"></li>';
    return false;
  }
}

function virusTotalSend($filepath,$filehash)
{
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
  }
  else {
    echo '<li class="list-group-item" style="background-color: green; color: white">'.$api_reply_array['positives']. '</li>';
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

function webCallAnalysis()
{

  $filecontent = file_get_contents(realpath('index.html'));
  '<li class="list-group-item">'.$filecontent.'</li>';

}




























 ?>
