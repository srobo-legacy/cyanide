<?php

$config = Configuration::getInstance();
$config->override("repopath", $testWorkPath);
$config->override("user.default", "bees");
$config->override("user.default.teams", array(1, 2));
$config->override("auth_module", "single");
$config->override('modules.always', array("file"));

//do a quick authentication
$auth = AuthBackend::getInstance();
test_true($auth->authUser('bees','face'), "authentication failed");

$projectManager = ProjectManager::getInstance();

section('slashes in name: create');
$projName = 'cake/face';
$repopath = $config->getConfig("repopath") . "/1/master/" . $projName . ".git";
$ret = $projectManager->createRepository(1, $projName);

test_false($ret, 'did not block creation of a project with / in the name');
test_false(is_dir($repopath), 'created repo with / in the name!');


section('slashes in name: copy');
$repopath2 = $config->getConfig("repopath") . "/1/master/" . 'cake' . ".git";
$projectManager->createRepository(1, 'cake');
test_true(is_dir($repopath2), 'Failed to create repo to copy');

$ret = $projectManager->copyRepository('cake', $projName);

test_false($ret, 'did not block copying of a project with / in the name');
test_false(is_dir($repopath), 'copied repo with / in the name!');

section('updateRepository: autosave contents');

$projName = 'face';
$repopath = $config->getConfig("repopath") . "/1/master/" . $projName . ".git";
$projectManager->createRepository(1, $projName);
test_existent($repopath, 'Failed to create project');

$repo = $projectManager->getUserRepository(1, $projName, 'jim');
test_nonnull($repo, "Failed to get repo: 1/$projName/jim");

$repo->putFile('committed', 'some committed content');
$repo->putFile('committed-autosave', 'some other committed content');

$repo->stage('committed');
$repo->stage('committed-autosave');

$repo->commit('commit message', 'jim', 'jim@someplace.com');
$repo->push();

// we've now got a repo with a couple of committed files.
// so, we modify the state of the checkout, as autosaves do

$repo->gitMKDir('some-folder');
$repo->putFile('committed-autosave', $committedContent = 'some autosaved content in a committed file');
$repo->putFile('autosave', $autosaveContent = 'some autosaved content');

$folder = $repo->workingPath().'/some-folder';

$autosavedFile = $repo->workingPath().'/autosave';
$autosavedCTime = filemtime($autosavedFile);

$committedFile = $repo->workingPath().'/committed-autosave';
$committedCTime = filemtime($committedFile);

// be sure there's a measureable time difference between before and after
sleep(1);
// clear the caches... PHP needs this to get sane answers from fileXtime or stat-related functions
clearstatcache();
// update
$projectManager->updateRepository(1, $projName, 'jim');
clearstatcache();

// test the result
test_existent($autosavedFile, 'Autosaved (uncommitted) files should remain after an update');
test_existent($folder, 'Empty folders should remain after an update');

test_equal($repo->getFile('autosave'), $autosaveContent, 'Content of autosaved (uncommitted) file should be preserved');
test_equal($repo->getFile('committed-autosave'), $committedContent, 'Content of committed file plus an autosave should be preserved');

test_equal(filemtime($autosavedFile), $autosavedCTime, 'Autosaved (uncommitted) file should have its modified time preserved through an update');
test_equal(filemtime($committedFile), $committedCTime, 'Committed file plus an autosave should have its modified time preserved through an update');
