<?php

require_once('include/auth/sso/client/SSOClient.php');
require_once('include/auth/secure-token.php');

class SSOAuth extends SecureTokenAuth
{
	private $ssoClient = null;
	private $pwd = null;

	public function __construct()
	{
		$config = Configuration::getInstance();
		$keyfile = $config->getConfig('sso.private_key');
		if (!$keyfile || !file_exists($keyfile))
		{
			throw new Exception('Cannot use SSO Authentication without a private key.', E_INTERNAL_ERROR);
		}

		$server_url = $config->getConfig('sso.server_url');
		if (!$server_url)
		{
			throw new Exception('Cannot use SSO Authentication without a server.', E_INTERNAL_ERROR);
		}

		$key = file_get_contents($keyfile);
		$this->ssoClient = new SSOClient($server_url, $key);
		$this->pwd = sha1($key);

		parent::__construct();

		if ($this->ssoClient->IsPostBack())
		{
			$this->handlePostBack();
		}
	}

	private function handlePostBack()
	{
		$data = $this->getData();
		$this->authUser($data->username, $this->pwd);

		// TODO: re-architect things so this doesn't appear here!
		getDefaultTokenStrategy()->setNextAuthToken($this->getNextAuthToken());

		// Get rid of annoying browser POST warnings.
		header('Location: ' . $_SERVER['REQUEST_URI']);
		exit();
	}

	private function getData()
	{
		$this->ssoClient->DoSSO();
		$data = $this->ssoClient->GetData();
		return $data;
	}

	public function checkAuthentication($username, $password)
	{
		$data = $this->getData();
		$matches = $data->username == $username && $this->pwd == $password;
		return $matches;
	}

	public function getTeams($username)
	{
		$data = $this->getData();
		$teams = array();

		// TODO: make this config key more agnostic?
		$groupNamePrefix = Configuration::getInstance()->getConfig('sso.team.prefix');
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
		$adminName = Configuration::getInstance()->getConfig('sso.admin_group');
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
		$this->ssoClient->Logout();
	}
}
