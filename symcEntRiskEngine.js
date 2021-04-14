var https = require('https');
var fs  = require('fs');
var path = require('path');


const NodeCache = require( "node-cache" );
const icaRiskCache = new NodeCache( { stdTTL: 0, checkperiod: 0 } );
const cloudsocRiskCache = new NodeCache( { stdTTL: 0, checkperiod: 0 } );


/*
  Set up server and services
*/

const express = require('express')
const app = express()

const bodyParser = require('body-parser');
const url = require('url');

//const port = 3000
//const host = "risk.iamdemo.broadcom.com";

let host = process.env.HOST || "0.0.0.0";
let port = process.env.PORT || 8080;
let ICA_baseUrl = process.env.ICA_HOST || 'riskfabric.iamdemo.broadcom.com';
let ICA_authn = process.env.ICA_AUTHN ||  'Basic YXBpdXNlcjpTeW00bm93IQ==';
let CASB_tenant = process.env.CASB_TENANT || 'bcm-demo110com';
let CASB_authn = process.env.CASB_AUTHN || 'Basic MjIzYjRiMThkODU3MTFlYThkNjIwMjc2YWRlOGNiZmI6Q1BGblN3U1JTZ2FoVXBEeExvbzNlOVgxU1FMMmpUYTJkQ29LRXVDanl1Zw==';

// Parse URL-encoded bodies (as sent by HTML forms)
//app.use(express.urlencoded());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
//app.use(express.json());




function storeCloudSoc (data) {
//   console.log(data);
//   console.log("PROCESSING CloudSoc DATA");

   const json = JSON.parse(data);

   if (json != undefined){
      for(var i=0; i<json.logs.length; i++)
      {
        var userId = (json.logs[i]).user;
//        console.log(" - USER - ", userId," - SCORE - ", (json.logs[i]).threat_score);
        cloudsocRiskCache.set(userId,(json.logs[i]));
      }
   }
}



function storeICA (userId,data) {
//   console.log(data);
//   console.log("PROCESSING ICA DATA");
   const json = JSON.parse(data);

   if (json != undefined){
       for(var i=0; i<json.Data.length; i++)
       {
//          var userId = (json.Data[i]).EntityName.match(/\(([^)]+)\)/)[1];
//          var userId = "david.smith@bcm-demo110.com";
//          console.log(" - USER - ", userId ," - SCORE - ", (json.Data[i]).RiskInfo.Overview.RiskScore);
          icaRiskCache.set(userId,json.Data[i]);
       }
   }
}


/*
  Call ICA / RiskFabric to get user risk score
*/
function icaRiskFabric(userId){

  return new Promise ((resolve,reject) => {
     const http = require('http');

//  const baseUrl = 'icademoe3.eastus2.cloudapp.azure.com';
//  const targetHeaders = {'Authorization' : 'Basic aWNhYXBpdXNlcjpTeW1jMjAyMCE='};
//
     var uid= userId.substr(0, userId.indexOf('@')); 
  
     const baseUrl = 'riskfabric.iamdemo.broadcom.com';
     let targetUrl = '/restapi/search?query=' + uid + '&entityType=User&fields=RiskInfo&pageIndex=0&pageSize=500';
     const targetHeaders = {'Authorization' : ICA_authn};

     const myArgs = {
       host: baseUrl,
       path: targetUrl,
       headers: targetHeaders,
       method: "GET"
     };
//     console.log('ICA RiskFabric - Request:');

  
     var connector = http.request(myArgs, (resp) => {
       console.log('Response from ICA RiskFabric - statusCode:', resp.statusCode);
  
       const respString = [];

       resp.on('data', (d) => {
           respString.push(d);
       });
       resp.on('end', function() {
           storeICA(userId,Buffer.concat(respString).toString('utf-8'));
           resolve(Buffer.concat(respString).toString('utf-8'));
       });
     }).end();

     connector.on('error', (e) => {
         console.log('Response from ICA RiskFabric - ERROR:');
         console.error(e);
         reject(e);
     });
  });

}



/*
  Call CloudSoc / ThreatDetect to get user risk score
*/
function cloudsocThreatDetect(userId){

  return new Promise ((resolve,reject) => {
     const https = require('https');

//     const userId = 'david.smith@bcm-demo110.com';

     const baseUrl = 'api-vip.elastica.net';
     let targetUrl = '/' + CASB_tenant + '/api/admin/v1/logs/get/?app=Detect&subtype=threatscore&threat_score=0,99&user='+userId;
//     const targetUrl = '/bcm-demo110com/api/admin/v1/logs/get/?app=Detect&subtype=threatscore&threat_score=0,99';
     const targetHeaders = {'Authorization' : CASB_authn ,
                          'X-Elastica-Dbname-Resolved':'True'};

     const myArgs = {
       host: baseUrl,
       path: targetUrl,
       headers: targetHeaders,
       method: "GET"
     };
//     console.log('CloudSoc ThreatDetect - Request:');

     var connector = https.request(myArgs, (resp) => {
        console.log('Response from CloudSoc ThreatDetect - statusCode:', resp.statusCode);
//    resp.pipe(res);

        const respString = [];

        resp.on('data', (d) => {
           respString.push(d);
        });
        resp.on('end', function() {
           storeCloudSoc(Buffer.concat(respString).toString('utf-8'));
           resolve(Buffer.concat(respString).toString('utf-8'));
        });

     }).end();

     connector.on('error', (e) => {
        console.log('Response from CloudSoc ThreatDetect - ERROR:');
        console.error(e);
        reject(e);
     });
   });
};

async function getRisk(res,userId) {

      let cloudsocRisk = await cloudsocThreatDetect(userId);
      if ( cloudsocRisk != undefined ){
         //console.log("Getting Cloudsoc Risk",cloudsocRisk);
      } ;

      let icaRisk = await icaRiskFabric(userId);
      if ( icaRisk != undefined ){
         //console.log("Getting ICA Risk",icaRisk);
      } ;


      let resp = { "subject": "undefined", 
                  "riskScore" : 0, 
                  "riskReason": "Risky Behaviour", 
                  "riskFactors": [], 
                  "riskAdvice": "deny", 
                  "msg": "Risk Evaluation Success",
                  "riskEvalContext": [{"key": "transactionId","value":"txnId-1234"},{"key":"deviceId","value":"device-1234"}]
               };
      let obj = JSON.parse(icaRisk);
      let dlp_severities = ["Low","Medium","Critical"];
      let dlp_threatScore=0;
      let dlp_riskRating=dlp_severities[0];
      dlp_threatScore = obj.Data[0].RiskInfo.Overview.RiskScore;
      dlp_riskRating = obj.Data[0].RiskInfo.Overview.RiskRating;
      console.log("\tDLP RiskScore: ",obj.Data[0].RiskInfo.Overview.RiskScore);
      console.log("\tDLP RiskRating: ",obj.Data[0].RiskInfo.Overview.RiskRating);
      for (let i = 0 ; i < obj.Data[0].RiskInfo.Vectors.length; i++) {
         console.log("\tDLP VECTORS: ",obj.Data[0].RiskInfo.Vectors[i].Name);
         resp.riskFactors.push(obj.Data[0].RiskInfo.Vectors[i].Name);
      }
      obj = JSON.parse(cloudsocRisk);
      let casb_severities = ["low","medium","high"];
      let casb_threatScore=0;
      let casb_riskRating=casb_severities[0];
      for (let i = 0 ; i < obj.logs.length; i++) {
         casb_threatScore = (parseInt(obj.logs[i].threat_score) > casb_threatScore) ? parseInt(obj.logs[i].threat_score) : casb_threatScore; 
         let a = casb_severities.indexOf(obj.logs[i].severity);
         let b = casb_severities.indexOf(casb_riskRating);
         if (a > b) { casb_riskRating = obj.logs[i].severity } ;
      }
      console.log("\tCASB RiskScore: ",casb_threatScore);
      console.log("\tCASB RiskRating: ",casb_riskRating);
      for (let i = 0 ; i < obj.logs.length; i++) {
         console.log("\tCASB VECTORS: ",obj.logs[i].service);
         resp.riskFactors.push(obj.logs[i].service);
      }

      let riskAdvice = ["allow","stepup","deny" ];
      resp.subject = userId;
      
      resp.riskScore = (casb_threatScore > dlp_threatScore) ? casb_threatScore : dlp_threatScore;
      resp.riskReason = (casb_threatScore > dlp_threatScore) ? "CloudSOC Threat Detection" : "Data Loss Prevention Threat Detection";
      resp.riskAdvice = (casb_threatScore > dlp_threatScore) ? riskAdvice[casb_severities.indexOf(casb_riskRating)] : riskAdvice[dlp_severities.indexOf(dlp_riskRating)];
      res.send(resp);
}


app.get('/', (req, res) => {
  res.send('Hello World!')
})


app.post('/PostUserRiskScoreEvaluator', (req, res) => {

   let resp = { "subject": "undefined", 
                  "msg" : "Post Risk evaluation successful", 
                  "clientRespContext": []
               };
   resp.subject = req.body.subject;
   console.log('/PostUserRiskScoreEvaluator for ',resp.subject);

   res.send(resp);
})


app.post('/UserRiskScoreEvaluator', (req, res) => {

  let userId = req.body.subject;

  console.log('/UserRiskScoreEvaluator for ',userId);

  
  if (userId != undefined) {
      getRisk(res,userId);
  }


  //res.send(resp);

})



app.listen(port,host, () => {
  console.log(`DLP+CASB RiskScore app listening at ${host}:${port}`)
})




app.get('/UserRiskScore', (req, res) => {

  let userId = req.query.userId;

  console.log('/UserRiskScore for ',userId);

  const json = { "userId": "undefined", "risks" : [{"riskSource": "CloudSOC", "risk":{}},{"riskSource": "RiskFabric", "risk":{}}] } ;
  
    if (userId == undefined) {
      json.userId = "undefined"; 
    } else {
      json.userId = userId;
  
      var risk = icaRiskCache.get(userId);
      if ( risk != undefined ){
         json.risks[1].riskSource = "RiskFabric";
         json.risks[1].risk = risk;
      } ;
      risk = cloudsocRiskCache.get(userId);
      if ( risk != undefined ){
         json.risks[0].riskSource = "CloudSOC";
         json.risks[0].risk = risk;
      } ;

  }


  var html = '<html><head><title>Symantec Enterprise Risk Engine</title></head><body>';


  html += '<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.0/css/bootstrap.min.css"><link href="https://fonts.googleapis.com/css?family=Montserrat" rel="stylesheet"><script src="https://ajax.googleapis.com/ajax/libs/jquery/3.4.1/jquery.min.js"></script><script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.0/js/bootstrap.min.js"></script>';


  html += "<style> .tabcontent { display: none; padding: 6px 12px; border: 1px solid #ccc; border-top: none; } </style>";


  html += '<style> body { font: 20px Montserrat, sans-serif;    line-height: 1.8;    color: #f5f6f7;  }  p {font-size: 16px;}  .margin {margin-bottom: 45px;}  .bg-1 {     background-color: #1abc9c; /* Green */    color: #ffffff;  }  .bg-2 {     background-color: #474e5d; /* Dark Blue */    color: #ffffff;  }  .bg-3 {     background-color: #ffffff; /* White */    color: #555555;  }  .bg-4 {     background-color: #2f2f2f; /* Black Gray */    color: #fff;  }  .container-fluid {    padding-top: 70px;    padding-bottom: 70px;  }  .navbar {    padding-top: 15px;    padding-bottom: 15px;    border: 0;    border-radius: 0;    margin-bottom: 0;    font-size: 12px;    letter-spacing: 5px;  }  .navbar-nav  li a:hover {    color: #1abc9c !important;  }  </style>';


  html += '<nav class="navbar navbar-default"> <div class="container">    <div class="navbar-header">      <button type="button" class="navbar-toggle" data-toggle="collapse" data-target="#myNavbar">        <span class="icon-bar"></span>        <span class="icon-bar"></span>        <span class="icon-bar"></span>                              </button>      <a class="navbar-brand" href="#">Symantec Enterprise Risk Engine</a>    </div>    </div></nav>';

  html += '<div class="container bg-1 text-center">  <h3 class="margin">Risk Profile Information for '+ req.query.userId +'</h3></div>';

  html += '<div class="container bg-2 text-center"> <br/>  <p>';
  
  var userLinks = ["https://app.elastica.net/static/ng/appThreats/index.html#/?severities=high&deeplink=users","http://riskfabric.iamdemo.broadcom.com/#/entities/persons/2143/detail"];

  html+= " <div class='tab'> ";
  html+= " <table><tr> ";
  html+= ' <td><button class="list-group-item list-group-item-success" onclick="changeRisk(event, \'CloudSOC\')" id="defaultOpen">CloudSOC</button></td> ';
  html+= ' <td><button class="list-group-item list-group-item-success" onclick="changeRisk(event, \'RiskFabric\')">RiskFabric</button></td> ';
  html+= " </tr></table></div> ";


  for (var i=0; i<json.risks.length; i++){
      html += "<div id="+ JSON.stringify(json.risks[i].riskSource,null,"\t")  +" class='tabcontent'>";
      html += '<ul class="list-group">';
      html += '<li class="list-group-item list-group-item-success" style="width:20%"> <a target="_blank" href='+ userLinks[i] +'>'+ (JSON.stringify(json.risks[i].riskSource,null,"\t")) +'</a></li>';
      html += '<li class="list-group-item list-group-item-success" style="text-align:left" ><pre>'+ (JSON.stringify(json.risks[i].risk,null,"\t")) +'</pre></li>';
      html += '</ul>  </p>  <br/>  <!-- <a href="#" class="btn btn-default btn-lg">    <span class="glyphicon glyphicon-search"></span> more about us?  </a> -->';
      html += "</div>";
  }

  html += "</div>";
  html += '<footer class="container bg-4 text-center">  <p><a href="#">Symantec Enterprise Risk Engine</a></p> </footer>';

html += "<script>"
html += "function changeRisk(evt, riskSource) { ";
html += "     var i, tabcontent, tablinks; ";

html += "     tabcontent = document.getElementsByClassName('tabcontent'); ";
html += "     for (i = 0; i < tabcontent.length; i++) { ";
html += "       console.log('TABCONTENT = ',tabcontent[i]);";
html += "       tabcontent[i].style.display = 'none'; ";
html += "     } ";

html += "     tablinks = document.getElementsByClassName('tablinks'); ";
html += "     for (i = 0; i < tablinks.length; i++) { ";
html += "       tablinks[i].className = tablinks[i].className.replace(' active', ''); ";
html += "     } ";
 
html += "     console.log('RISKSOURCE = ',riskSource);";
html += "     document.getElementById(riskSource).style.display = 'block'; ";
html += "     evt.currentTarget.className += ' active'; ";
html += "  }";
html += "</script>"


html += "<script>"
html += "document.getElementById('defaultOpen').click();";
html += "</script>"


  html += "</body></html>";



  res.send(html);

//  res.send(json);
})
