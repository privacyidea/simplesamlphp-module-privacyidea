You can freely customize the module.

You can adjust to your needs the one which is already available or build a new one.

E.g. If you want to use dark theme in UCS, you may want to change the input's and button's font color.

Change the font color in CSS with the following:

      button, input { color: black !important; }


To use the Google theme for login, you need to:

1. Add 

       "theme.use" => "privacyidea:google",
   
   to your ``config.php`` file.


2. Set up a directory ``/css`` in the webserver pointing to: ``/usr/share/simplesamlephp/modules/privacyidea/themes/google/css``. 


On Apache you can paste the following to /etc/apache2/sites-available/foo-saml.conf:
 
      Alias /css /usr/share/simplesamlphp/modules/privacyidea/themes/google/css
      <Directory /usr/share/simplesamlphp/modules/privacyidea/themes/google/css>
         Require all granted
      </Directory>