var counter = 0;

document.addEventListener("DOMContentLoaded", function (event) {
  document.querySelector("#btn").addEventListener("click", function () {
    document.querySelector("#container").innerHTML = counter++;
  });

  document.querySelector("#foo").insertAdjacentHTML("afterend", "<i>First party injected text</i><img src='notexisting' onerror='console.log(\"First party: insertAdjacentHTML\")' />");
});
