$( document ).ready(function() {

  // Enable Bootstrap tooltips
  $(function (){$('[data-toggle="tooltip"]').tooltip({container: 'body'})})

  // Profile image upload
  $("#profile-img").on('click', () => {
    $("#file-selector").click()
  })
  $("#file-selector").on('change', () => {
    $('#upload-button').css('display', 'block')
  })

  $("#fileUpload").on('change', () => {
    $('#fileNameUpload').html($("#fileUpload").val());
  })

  $('.fallback-img')
    .on('error', function () {
      $(this).attr('src', '/images/profile.png');
    })
    .attr('src', function () {
      // Get the value from the data-src attribute
      return $(this).data('src');
    });
});
