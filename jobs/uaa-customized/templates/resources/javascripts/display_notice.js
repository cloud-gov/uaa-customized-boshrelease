var login = document.querySelector('.js-full_login');
var notice = document.querySelector('.js-notice');
var noticeReadMore = document.querySelector('.js-notice-read_more');
var noticeSubmit = document.querySelector('.js-notice-submit');
var noticeMoreInformation = document.querySelector(
    '.js-notice-more_information');
var noticeMoreInformationDismiss = document.querySelectorAll(
    '.js-notice-more_information-dismiss');
login.style.display = 'none';
noticeReadMore.addEventListener('click', function(ev) {
    ev.preventDefault();

    noticeMoreInformation.style.display = 'block';
    noticeMoreInformation.style.opacity = 100;
});
for (var i = 0; i < noticeMoreInformationDismiss.length; i++) {
    noticeMoreInformationDismiss[i].addEventListener('click', function(ev) {
        ev.preventDefault();
        noticeMoreInformation.style.opacity = 0;
        noticeMoreInformation.style.display = 'none';
    });
}
noticeSubmit.addEventListener('click', function(ev) {
    ev.preventDefault();
    login.style.display = 'block';
    notice.style.display = 'none';
});

(function(root) {
  var cloudGovRegexp = new RegExp(/\.?cloud\.gov/);
  var referrer = root.document.referrer;
  var node = root.document.getElementById('cli-info');

  if (cloudGovRegexp.test(referrer)) {
    node.className = node.className.replace(/hidden/g, '');
  }
})(window);