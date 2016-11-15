To use the Google like theme for login, you need to:

1. add 

       "theme.use" => "privacyidea:google",
   
   to your ``config.php`` file.
   
2. Setup a directory ``/css`` in the webserver pointing to 
``/usr/share/simplesamlephp/modules/privacyidea/themes/google/css``. On Apache
 you can do it like this:
 
          Alias /css /usr/share/simplesamlphp/modules/privacyidea/themes/google/css
          <Directory /usr/share/simplesamlphp/modules/privacyidea/themes/google/css>
              Require all granted
          </Directory>           
          
 