<?php

require_once('include/auth/external-auth/client/SSOClient.php');
require_once('include/auth/secure-token.php');

class SRExternalAuth extends SecureTokenAuth
{
	private $ssoClient = null;
	private $data = null;

	public function __construct()
	{
		$config = Configuration::getInstance();
		$private_keyfile = $config->getConfig('external_auth.private_key');
		if (!$private_keyfile || !file_exists($private_keyfile))
		{
			throw new Exception('Cannot use SR External Authentication without a private key.', E_INTERNAL_ERROR);
		}

		$public_keyfile = $config->getConfig('external_auth.public_key');
		if (!$public_keyfile || !file_exists($public_keyfile))
		{
			throw new Exception('Cannot use SR External Authentication without a public key.', E_INTERNAL_ERROR);
		}

		$server_url = $config->getConfig('external_auth.server_url');
		if (!$server_url)
		{
			throw new Exception('Cannot use SR External Authentication without a server.', E_INTERNAL_ERROR);
		}

		$private_key = file_get_contents($private_keyfile);
		$public_key = file_get_contents($public_keyfile);
		$this->ssoClient = new SSOClient($server_url, $private_key, $public_key);

		parent::__construct();
	}

	private function handlePostBack($data)
	{
		// This isn't a very nice way to handle this.
		// Perhaps we should rework secure-token to allow subclasses to
		// more easily store stuff in the token.
		$pwd = json_encode($data);
		$this->authUser($data->username, $pwd);
		// Ideally we wouldn't do token setting here, but I couldn't find a
		// way to achieve the auth setup that didn't do this.
		getDefaultTokenStrategy()->setNextAuthToken($this->getNextAuthToken());
		// Redirect to self (we're in the index page call here) to avoid
		// nasty POST warnings
		header("Location: .");
	}

	public function validateAuthToken($token)
	{
		if ($token === null)
		{
			// possibly redirect to external provider
			// alternatively, loads up the data we've got back
			$data = $this->ssoClient->DoSSO();

			$this->handlePostBack($data);
		}
		$ret = parent::validateAuthToken($token);
		return $ret;
	}

	private function getData()
	{
		if ($this->data == null)
		{
			$this->data = $this->ssoClient->GetData();
		}
		return $this->data;
	}

	public function checkAuthentication($username, $password)
	{
		// if we get this far, we know the username is valid.
		$this->data = json_decode($password);
		return true;
	}

	public function getTeams($username)
	{
		$data = $this->getData();
		$teams = array();

		// TODO: make this config key more agnostic?
		$groupNamePrefix = Configuration::getInstance()->getConfig('external_auth.team.prefix');
		foreach ($data->groups as $group)
		{
			if (stripos($group, $groupNamePrefix) === 0)
			{
				$teams[] = substr($group, strlen($groupNamePrefix));
			}
		}
		return $teams;
	}

	public function isCurrentUserAdmin()
	{
		// TODO: make this config key more agnostic?
		$adminName = Configuration::getInstance()->getConfig('external_auth.admin_group');
		$data = $this->getData();

		$isAdmin = in_array($adminName, $data->groups);
		return $isAdmin;
	}

	public function displayNameForTeam($team)
	{
		return "Team $team";
	}

	public function displayNameForUser($user)
	{
		$data = $this->getData();
		$dn = $data->displayName;
		return $dn;
	}

	public function emailForUser($user)
	{
		return $user . "@" . (isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'example.com');
	}

	public function deauthUser()
	{
		parent::deauthUser();
		$next = $this->ssoClient->GetLogoutUri();
		Output::getInstance()->setOutput('next', $next);
	}
}
