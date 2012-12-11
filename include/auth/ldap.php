<?php

require_once("include/auth/secure-token.php");
require_once("include/ldap.php");
/**
 * A class for doing LDAP authentication using the secure token system
 * implements SecureTokenAuth
 * @author Sam Phippen <samphippen@googlemail.com>
 */
class LDAPAuth extends SecureTokenAuth
{
	private $ldapManager;

	public function __construct()
	{
		parent::__construct();
	}

	public function checkAuthentication($username, $password)
	{
		$config = Configuration::getInstance();
		$this->ldapManager = new LDAPManager($config->getConfig("ldap.host"), $username, $password);
		return $this->ldapManager->getAuthed();
	}

	public function getTeams($username)
	{
		$config = Configuration::getInstance();
		$ldapManager = new LDAPManager($config->getConfig("ldap.host"), "ide", $config->getConfig("ldap.ideuser.password"));
		$groupNamePrefix = $config->getConfig("ldap.team.prefix");
		$groups = $ldapManager->getGroupsForUser($username, $groupNamePrefix.'*');
		$teams = array();

		foreach ($groups as $group)
		{
			$teams[] = substr($group, strlen($groupNamePrefix));
		}

		return $teams;
	}

	public function isCurrentUserAdmin()
	{
		$config = Configuration::getInstance();
		$adminName = $config->getConfig("ldap.admin_group");
		$user = $this->ldapManager->getUser();
		$IDEldapManager = new LDAPManager($config->getConfig("ldap.host"), "ide", $config->getConfig("ldap.ideuser.password"));
		$groups = $IDEldapManager->getGroupsForUser($user, $adminName);
		// should either be 0 or 1 responses...
		$isAdmin = count($groups) > 0;
		return $isAdmin;
	}

	public function displayNameForUser($user)
	{
		if ($this->ldapManager->getAuthed())
		{
			$info = $this->ldapManager->getUserInfo($user);
			return $info["name.first"] . " " . $info["name.last"];
		}
		else
		{
			throw new Exception("you aren't authed to ldap", E_LDAP_NOT_AUTHED);
		}
	}

	public function emailForUser($user)
	{
		if ($this->ldapManager->getAuthed())
		{
			$info = $this->ldapManager->getUserInfo($user);
			return $info["email"];
		}
		else
		{
			throw new Exception("you aren't authed to ldap", E_LDAP_NOT_AUTHED);
		}
	}
}
