<?php

/**
 * Simple Webservice authentication source
 *
 * This class is an example authentication source which authenticates an user
 * against a webservice.
 *
 * @package simpleSAMLphp
 * @version $Id$
 */
class sspmod_webserviceauth_Auth_Source_SOAP extends sspmod_core_Auth_UserPassBase {


    /**
     * The url of the webservice.
     */
    private $url;

    /**
     *  If the webservice is protected by Auth-Basic, set the username.
     */
    private $authbasic_user;

    /**
     *  If the webservice is protected by Auth-Basic, set the password.
     */
    private $authbasic_password;

    /**
     *  The template file where we will introduce the login form crendentials
     *  (this file should exists in the 'templates' folder of the module)
     *  {{USER}} and {{PASSWORD}} will be replaced in the template.
     */
    private $template;

    /**
     *  This regular expression will be search in the webservice response in order to determine
     *  if the user was   or not authenticated in the webservice
     *
     */
    private $success_expr;

    /**
     *  In order to determine if the user was or not authenticated in the webservice
     */
    private $attrs_expr;

    /**
     * The userid of the login form will be returned in the attributes array with this name. 
     * By default 'username'
     */
    private $idfield='username';

    /**
     * Constructor for this authentication source.
     *
     * @param array $info  Information about this authentication source.
     * @param array $config  Configuration.
     */
    public function __construct($info, $config) {
        assert('is_array($info)');
        assert('is_array($config)');

        /* Call the parent constructor first, as required by the interface. */
        parent::__construct($info, $config);

        /* Make sure that all required parameters are present. */
        foreach (array('url', 'template', 'success_expr') as $param) {
            if (!array_key_exists($param, $config)) {
                throw new Exception('Missing required attribute \'' . $param .
                    '\' for authentication source ' . $this->authId);
            }

            if (!is_string($config[$param])) {
                throw new Exception('Expected parameter \'' . $param .
                    '\' for authentication source ' . $this->authId .
                    ' to be a string. Instead it was: ' .
                    var_export($config[$param], TRUE));
            }

            $module_path = SimpleSAML_Module::getModuleDir('webserviceauth');
            $template_path = $module_path.'/templates/'.$config['template'];
            if (!file_exists($template_path)) {
                throw new Exception('Template file not found: '.$template_path);
            }
        }

        $this->url = $config['url'];
        $this->template = $template_path;
        $this->success_expr = $config['success_expr'];

        if (!isset($config['idfield'])) {
            $this->idfield = 'username';
        } else {
            $this->idfield = $config['idfield'];
        }

        if (isset($config['authbasic.user']) && isset($config['authbasic.password'])) {
            $this->authbasic_user = $config['authbasic.user'];
            $this->authbasic_password = $config['authbasic.password'];
        }

        if (isset($config['attrs_expr']) && !empty($config['attrs_expr'])) {
            $this->attrs_expr = $config['attrs_expr'];
        }

        if (isset($config['namespaces']) && !empty($config['namespaces'])) {
            $this->namespaces = $config['namespaces'];
        }
    }

    /**
     * Do the webservice request
     */
    protected function doRequest($username, $password) {
        $webservice_body = file_get_contents($this->template);
        $webservice_body = str_replace('{{USER}}', $username, $webservice_body);
        $webservice_body = str_replace('{{PASSWORD}}', $password, $webservice_body);

        $headers = array(
            "Content-type: text/xml;charset=\"utf-8\"",
            "Accept: text/xml",
            "Cache-Control: no-cache",
            "Pragma: no-cache",
            "Content-length: ".strlen($webservice_body),
        );

        // PHP cURL  for https connection with auth
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
        curl_setopt($ch, CURLOPT_URL, $this->url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 60);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $webservice_body); // the SOAP request
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

        if (!empty($this->authbasic_user)) {
            curl_setopt($ch, CURLOPT_USERPWD, $this->authbasic_user . ":" . $this->authbasic_password);
        }

        $response = curl_exec($ch);
        curl_close($ch);

        return $response;
    }

    /**
     * Attempt to log in using the given username and password.
     *
     * On a successful login, this function should return the users attributes. On failure,
     * it should throw an exception. If the error was caused by the user entering the wrong
     * username or password, a SimpleSAML_Error_Error('WRONGUSERPASS') should be thrown.
     *
     * Note that both the username and the password are UTF-8 encoded.
     *
     * @param string $username  The username the user wrote.
     * @param string $password  The password the user wrote.
     * @return array  Associative array with the users attributes.
     */
    protected function login($username, $password) {
        assert('is_string($username)');
        assert('is_string($password)');

        // Webservice code
        $response = $this->doRequest($username, $password);

        // Check
        if (preg_match($this->success_expr, $response) !== 1) {
            throw new SimpleSAML_Error_Error('WRONGUSERPASS');
        }

        $attributes = array(
            $this->idfield => array($username)
        );

        if (!empty($this->attrs_expr)) {
            try {
                $doc = new DOMDocument();
                $doc->loadXML($response);

                $xpath = new DOMXpath($doc);

                if (isset($this->namespaces) && !empty($this->namespaces)) {
                    foreach($this->namespaces as $key => $value) {
                        $xpath->registerNamespace($key, $value);
                    }
                }
                foreach ($this->attrs_expr as $name => $expr_array) {
                    $attributes[$name] = array();
                    $nodes = $xpath->query($expr_array);
                    foreach($nodes as $node) {
                        $value = trim($node->nodeValue);
                        if (strpos($value, "\n") !== FALSE) {
                            $attributes[$name][] = explode("\n", trim($node->nodeValue));
                        } else {
                            $attributes[$name][] = $value;
                        }
                    }
                }
            } catch (Exception $e) {}
        }
        print_r($attributes);exit();

        SimpleSAML_Logger::info('webserviceauth:' . $this->authId . ': Attributes: ' .
            implode(',', array_keys($attributes)));

        return $attributes;
    }

}

?>