document.addEventListener("DOMContentLoaded", function () {
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    var url = tabs[0].url;
    document.getElementById("url-input").value = url;
  });

  document
    .getElementById("url-form")
    .addEventListener("submit", function (event) {
      event.preventDefault();
      var url = document.getElementById("url-input").value;
      // console.log(url);
    });
});

document
  .getElementById("check-button")
  .addEventListener("click", function checkPhishing(url) {
    console.log(url);
  });
