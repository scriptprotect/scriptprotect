document.addEventListener("DOMContentLoaded", function (event) {
    document.querySelector("#first-benign").addEventListener("click", function () {
        document.querySelector("#foo").insertAdjacentHTML("afterend", "<img src='img/first-benign.png' />");
    })
    document.querySelector("#first-code").addEventListener("click", function () {
        document.querySelector("#foo").insertAdjacentHTML("afterend", "<img src='img/first-code.png' onload='alert(\"First party\")' />");
  });
});
