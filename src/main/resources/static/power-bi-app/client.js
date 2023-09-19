const config = {
clientId: "power-bi-app",
clientSecret: "powerBi123",
authorizeUrl: "http://localhost:9000/oauth/authorize",
tokenUrl: "http://localhost:9000/oauth/token",
callbackUrl: "http://localhost:8082",
patientsUrl: "http://localhost:8080/v1/patients"
};

let accessToken = "";

function search() {
alert("Using access token " + accessToken);

$.ajax({
url: config.patientsUrl,
type: "get",

beforeSend: function(request) {
request.setRequestHeader("Authorization", "Bearer " + accessToken);
},

success: function(response) {
var json = JSON.stringify(response);
$("#results").text(json);
},

error: function(error) {
alert("Error trying to retrieve data");
}
});
}

function generateAccessToken(code) {
alert("Providing access using code " + code);

let clientAuth = btoa(config.clientId + ":" + config.clientSecret);

let params = new URLSearchParams();
params.append("grant_type", "authorization_code");
params.append("code", code);
params.append("redirect_uri", config.callbackUrl);

$.ajax({
url: config.tokenUrl,
type: "post",
data: params.toString(),
contentType: "application/x-www-form-urlencoded",

beforeSend: function(request) {
request.setRequestHeader("Authorization", "Basic " + clientAuth);
},

success: function(response) {
accessToken = response.access_token;

alert("Access token granted: " + accessToken);
},

error: function(error) {
alert("Erro trying to generate access key");
}
});
}

function login() {
// https://auth0.com/docs/protocols/oauth2/oauth-state
let state = btoa(Math.random());
localStorage.setItem("clientState", state);

window.location.href = `${config.authorizeUrl}?response_type=code&client_id=${config.clientId}&state=${state}&redirect_uri=${config.callbackUrl}`;
}

$(document).ready(function() {
let params = new URLSearchParams(window.location.search);

let code = params.get("code");
let state = params.get("state");
let currentState = localStorage.getItem("clientState");

if (code) {
// window.history.replaceState(null, null, "/");

if (currentState == state) {
generateAccessToken(code);
} else {
alert("Invalid state");
}
}
});

$("#btn-search").click(search);
$("#btn-login").click(login);