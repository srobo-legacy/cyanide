<?php

$config = Configuration::getInstance();
$config->override('modules.always', array('multi'));
$config->override('modules.lazy', array('fake'));

$mm = ModuleManager::getInstance();
$mm->importModules();

// Hack the import path so that we can use our fake module.
$dir = dirname(__file__);
chdir($dir);

$multi = $mm->getModule('multi');
$fake = $mm->getModule('fake');

$input = Input::getInstance();
$output = Output::getInstance();

$fake->setHandler(function($cmd) use ($input, $output, $wasCalled) {
	var_dump($cmd);
	$a = $input->getInput('a', true);
	$b = $input->getInput('b', true);
	$c = $input->getInput('c', true);

	$out = $output->encodeOutput();
	test_equal($out, "{}", "Output should be empty to start with");

	$output->setOutput('my-cmd', $cmd);

	subsection('Check request module & command in the Input');
	$rqMod = $input->getRequestModule();
	test_equal($rqMod, 'multi:fake', 'Requested module');
	$rqCmd = $input->getRequestCommand();
	test_equal($rqCmd, $cmd, 'Requested module');

	subsection('Check command-specific Inputs');
	switch($cmd)
	{
		case 'first':
		{
			test_true($a, "Input 'a' should be true in the first command");
			test_false($b, "Input 'b' should be false in the first command");
			test_null($c, "Input 'c' should be null in the first command");
			$output->setOutput('bees', 'something');
			break;
		}
		case 'second':
		{
			test_null($a, "Input 'a' should be null in the second command");
			test_true($b, "Input 'b' should be true in the second command");
			test_false($c, "Input 'c' should be false in the second command");
			$output->setOutput('cheese', 'something-else');
			break;
		}
		default:
		{
			test_unreachable("Unexpected command '$cmd' dispatched");
		}
	}
});

$input->setInput('a', 'a');
$input->setInput('b', 'b');
$input->setInput('c', 'c');

$input->setInput('commands', array(
	array('cmd' => 'fake/first',
	      'data' => array('a' => true, 'b' => false)),
	array('cmd' => 'fake/second',
	      'data' => array('b' => true, 'c' => false))
));

section('Dispatch Command');
test_true($multi->dispatchCommand('independent'), "Failed to dispatch command multi/independent");

section('Check commands were executed');
$subCommandsDispatched = $fake->getCommands();
$expectedCommands = array('first', 'second');
test_equal($subCommandsDispatched, $expectedCommands, "Wrong sub-commands dispatched");

section('Check overall output');
$firstOut = $output->getOutput('fake/first');
$expectedFirstOut = array('my-cmd' => 'first', 'bees' => 'something');
test_equal($firstOut, $expectedFirstOut, 'Wrong output for first command');

$secondOut = $output->getOutput('fake/second');
$expectedSecondOut = array('my-cmd' => 'second', 'cheese' => 'something-else');
test_equal($secondOut, $expectedSecondOut, 'Wrong output for second command');

