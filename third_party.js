document.addEventListener("DOMContentLoaded", function (event) {
    document.querySelector("#third-benign").addEventListener("click", function () {
        document.querySelector("#foo").insertAdjacentHTML("afterend", "<img src='img/third-benign.png' />");
    })
    document.querySelector("#third-code").addEventListener("click", function () {
        document.querySelector("#foo").insertAdjacentHTML("afterend", "<img src='img/third-code.png' onload='alert(\"Third party\")' />");
  });
});
