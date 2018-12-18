var newdiv = document.createElement("DIV");
document.body.appendChild(newdiv);
newdiv.innerHTML = "<br /><br /><b>Third party injected code</b><img src=/ onerror='console.log(\"Third party: innerHTML\");'>"

document.querySelector("#foo").insertAdjacentHTML("afterend", "<i>Third party injected text</i><img src='notexisting' onerror='console.log(\"Third party: insertAdjacentHTML\")' />");
document.write("<script>console.log(\"Third party: document.write\")</script>");
