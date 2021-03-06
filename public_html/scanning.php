<?php

$total = 100;
$safe = 0;
$unsafe = 0;
$msg = "Il file sembra sicuro!";


//Funzione di controllo dell'hash
function hashCheck($filename)
{
  global $safe, $unsafe;
  $col = 'mysql:host=localhost;dbname=lightsid_malwarescan';
  $user = "lightsid_cecca";
  $pass = "cristiano";

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
  $col = 'mysql:host=localhost;dbname=lightsid_malwarescan';
  $user = "lightsid_cecca";
  $pass = "cristiano";
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

//Analisi sul database remoto di VirusTotal mediante API apposite
function virusTotalSend($filepath,$filehash)
{
  global $safe, $unsafe;
  $virustotal_api_key = '926d4d760ed7c7fcb5b70f8f35907b580a3f06a40889ad678c7683033628ace6'; //SENSIBILE: qui inseriamo la nostra api-key
  $file_name_with_full_path = realpath('/uploads/'.$filepath); //Formiamo il percorso del file
  $cfile = curl_file_create($file_name_with_full_path); //Creiamo un file da inviare mediante curl
  $report_url = 'https://www.virustotal.com/vtapi/v2/file/report?apikey='.$virustotal_api_key."&resource=".$filehash; //Il link a cui inviare i dati
  $ch = curl_init();
  curl_setopt($ch, CURLOPT_URL, $report_url); //impostiamo la richiesta curl
  curl_setopt ($ch, CURLOPT_RETURNTRANSFER, 1);
  $content = curl_exec ($ch); //eseguiamo la richiesta e mettiamo il risultato nella variabile
  curl_close ($ch);//chiudiamo la richiesta

  $api_test = json_decode($content,true); //decodifichiamo la risposta json


//Se il codice è -2, cioè richiesta in coda, visualizziamo un messaggio
  if($api_test['response_code']==-2){
    echo '<div class="card-header"><h6 align="center"> Il file è in coda per essere analizzato.. riprova più tardi. </h6></div>';
    echo '<div class="card-header"><div align="center"><img src="imgs/sadface.png" height="40"></div></div>';
}

// Se otteniamo risposta positiva
if($api_test['response_code']==1){
  echo '<div class="card-header"><h6> Numero positivi </h6></div>';
  if($api_test['positives']>0)
  {
    echo '<li class="list-group-item" style="background-color: red; color: white">'.$api_test['positives']. '</li>';
    $unsafe = $unsafe + 30;
  }
  else {
    echo '<li class="list-group-item" style="background-color: green; color: white">'.$api_test['positives']. '</li>';
    $safe = $safe + 30;
  }
  echo '<div class="card-header"><h6> Numero antivirus </h6></div>';
  echo '<li class="list-group-item">'.$api_test['total']. '</li>';
  echo '<div class="card-header"><h6> Timestamp ultima scansione </h6></div>';
  echo '<li class="list-group-item">'.$api_test['scan_date']. '</li>';
}

if($api_test['response_code']==0)
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

//Analisi delle chiamate web del file: url
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
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $report_url);
    curl_setopt ($ch, CURLOPT_RETURNTRANSFER, 1);
    $content = curl_exec ($ch);
    curl_close ($ch);

    $api_test = json_decode($content,true);
    if($api_test['response_code']==1)
    {
      if($api_test['positives']>0)
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

//Analisi della menzione di eventuali registri di sistema
function regAnalysis($filename)
{
global $safe, $unsafe;
  //Il contenuto del file dentro la variabile
  $filecontent = file_get_contents("uploads/".$filename);
  //Cerchiamo tutti i match di url validi
  preg_match_all('/HKEY_LOCAL_MACHINE.{1,100}/', $filecontent, $found);

  $numregs = substr_count($filecontent, 'HKEY_LOCAL_MACHINE'); //contiamo il numero di riferimenti a registri

  if($numregs>0) //se è maggiore di zero
    {
      echo '<li class="list-group-item" style="background-color: red; color: white">'.$numregs . '<span class="badge badge-danger">Almeno un riferimento a registri!</span>'; //barra rossa
      $unsafe = $unsafe + 40;

      echo '<div class="dropdown" style="position: absolute; right:3px; top:5px;">
      <button class="btn btn-secondary dropdown-toggle" type="button" id="dropdownMenuButton" data-toggle="dropdown" aria-haspopup="true" aria-expanded="true">
        Visualizza registri
      </button>
      <div class="dropdown-menu" aria-labelledby="dropdownMenuButton">';
      //Elenco dei registri trovati
      for($i=0;$i<count($found[0]);$i++)
      {
        echo '<a class="dropdown-item">'. $found[0][$i].'</a>';
      }
      echo'</div> </div></li>';
    }
    else {
      echo '<li class="list-group-item" style="background-color: green; color: white">'.$numregs . '</li>'; //barra verde
      $safe = $safe + 10;

    }

}

//Analisi sulla presenza di parole chiave che autodefiniscono il file o risultano sospette
function wordAnalysis($filename)
{
global $safe, $unsafe;
  //Il contenuto del file dentro la variabile
  $filecontent = file_get_contents("uploads/".$filename);
  //Cerchiamo tutti i match di url validi
  preg_match_all('/malware|virus|ransom|bitcoin|BTC|spyware|spy|ransomware/', $filecontent, $words);


  if(count($words[0])>0) //se è maggiore di zero
    {
      echo '<li class="list-group-item" style="background-color: orange; color: white">'.count($words[0]) . '<span class="badge badge-warning">Almeno una parola chiave trovata!</span>'; //barra rossa
      $unsafe = $unsafe + 20;

      echo '<div class="dropdown" style="position: absolute; right:3px; top:5px;">
      <button class="btn btn-secondary dropdown-toggle" type="button" id="dropdownMenuButton" data-toggle="dropdown" aria-haspopup="true" aria-expanded="true">
        Visualizza parole
      </button>
      <div class="dropdown-menu" aria-labelledby="dropdownMenuButton">';
      //Elenco dei registri trovati
      for($i=0;$i<count($words[0]);$i++)
      {
        echo '<a class="dropdown-item">'. $words[0][$i].'</a>';
      }
      echo'</div> </div></li>';
    }
    else {
      echo '<li class="list-group-item" style="background-color: green; color: white">'. '0' . '</li>'; //barra verde
      $safe = $safe + 5;

    }

}

//Analisi della presenza di variabili di sistema
function varAnalysis($filename)
{
global $safe, $unsafe;
  //Il contenuto del file dentro la variabile
  $filecontent = file_get_contents("uploads/".$filename);
  //Cerchiamo tutti i match di url validi
  preg_match_all('/%.{1,20}.%/', $filecontent, $vars);


  if(count($vars[0])>0) //se è maggiore di zero
    {
      echo '<li class="list-group-item" style="background-color: red; color: white">'.count($vars[0]) . '<span class="badge badge-danger">Almeno una variabile trovata!</span>'; //barra rossa
      $unsafe = $unsafe + 10;

      echo '<div class="dropdown" style="position: absolute; right:3px; top:5px;">
      <button class="btn btn-secondary dropdown-toggle" type="button" id="dropdownMenuButton" data-toggle="dropdown" aria-haspopup="true" aria-expanded="true">
        Visualizza variabili
      </button>
      <div class="dropdown-menu" aria-labelledby="dropdownMenuButton">';
      //Elenco dei registri trovati
      for($i=0;$i<count($vars[0]);$i++)
      {
        echo '<a class="dropdown-item">'. $vars[0][$i].'</a>';
      }
      echo'</div> </div></li>';
    }
    else {
      echo '<li class="list-group-item" style="background-color: green; color: white">'. '0' . '</li>'; //barra verde
      $safe = $safe + 5;

    }

}


//Analisi della presenza di indirizzi IP sospetti
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
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $report_url);
    curl_setopt ($ch, CURLOPT_RETURNTRANSFER, 1);
    $content = curl_exec ($ch);
    curl_close ($ch);

    $api_test = json_decode($content,true);
    if($api_test['response_code']==1)
    {
      if($api_test['positives']>0)
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

//Stampa del risultato con banner finale
function finalSafety()
{
  global $safe, $unsafe,$msg;
  echo '<div class="col-sm">';
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
  <li class="list-group-item" style="background-color: black; color: white">'. $msg . '</li>
  </div>
</div>';


}

//Calcola il messaggio da mostrare all'utente come definitivo risultato
function determineMsg()
{
  global $safe, $unsafe,$msg;
  switch($num = $safe - $unsafe)
  {
    case($num<-50):
    $msg = $num . "Il file è infetto, eliminalo!";
    break;

    case($num>-50&&$num<-40):
    $msg = "Il file è pericoloso, analizzalo con un antivirus!";
    break;

    case($num>-40&&$num<-30):
    $msg =  "Il file è sicuramente pericoloso, dovresti eliminarlo!";
    break;

    case($num>-30&&$num<-10):
    $msg = "Il file è incerto, riprova ad analizzare.";
    break;

    case($num<0&&$num>-10):
    $msg = "Il file potrebbe essere infetto.";
    break;

    case $num==0:
    $msg = "Il file è incerto!";
    break;

    case ($num>0&&$num<=10):
      $msg = "Il file è probabilmente sicuro, ma tienilo d'occhio!";
      break;

    case ($num<=20&&$num>10):
      $msg =  "Il file è molto probabilmente sicuro!";
      break;

    case ($num>20&&$num<30):
    $msg =  "Il file è ragionevolmente sicuro!";
    break;

    case($num>=30&& $num<50):
    $msg = "Il file è sicuramente innocuo!";
    break;

    case($num>=50):
    $msg =  "Il file è innocuo, nessun problema!";
    break;



  }

}





















 ?>
