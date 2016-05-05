<?php

namespace Pagewiser\Security\Password\Tests;

use Pagewiser\Security\Password\Strength;

/**
 * Password strength test
 *
 * @group security
 */
class StrengthTest extends \PHPUnit_Framework_TestCase
{

	private $noRules = [
		'upperCase' => FALSE,
		'lowerCase' => FALSE,
		'number' => FALSE,
		'specialSymbol' => FALSE,
		'minLength' => NULL,
		'maxLength' => NULL,
	];

	public function providerRandomPasswords()
	{
		return [
			['asdf'],
			['ASDF'],
			['a'],
			['aA9'],
			['94596'],
			['#$%#'],
			['ASD*($#JKS*()DFU&SDFSSDF()#$853490AKOf094u5A'],
		];
	}

	public function providerSymbolPasswords()
	{
		return [
			['asdf'],
			['ASDF'],
			['a'],
			['aA9'],
			['94596'],
			['#$%#'],
			['ASD*($#JKS*()DFU&SDFSSDF()#$853490AKOf094u5A'],
		];
	}


	public function providerComparePasswords()
	{
		return [
			['asA9#', 'strongpassword'],
			['a$%5;', 'aA9$'],
			['abr12', 'Aasdfqw'],
			['Aasdfqw', 'asdf#$12'],
			['asdf#$12', 'AFasd22#$'],
			['AFasd22#$', 'ASDasdf@#$12'],
		];
	}


	public function providerCompareSimilarPasswords()
	{
		return [
			['1234', 'asdf'],
			['asdf', 'ASDF'],
		];
	}


	public function providerPasswordsStrength()
	{
		return [
			['asdf', Strength::WEAK],
			['ASDF', Strength::WEAK],
			['strongpassword', Strength::AVERAGE],
			['a$%5;', Strength::WEAK],
			['a12br', Strength::WEAK],
			['AFasd22#$', Strength::STRONG],
			['abr12', Strength::WEAK],
			['Aasdfqw', Strength::WEAK],
			['asdf#$12', Strength::AVERAGE],
			['AFasd22#$', Strength::STRONG],
			['ASDasdf@#$12', Strength::SECURE],
		];
	}


	/**
	 * @dataProvider providerRandomPasswords
	 */
	public function test_isValid_noRequirement_passAnyPassword($password)
	{
		$validation = new Strength();
		$validation->setRequirements($this->noRules);

		$this->assertTrue($validation->isValid($password));
	}


	public function test_isValid_requireUpperCase_passWithUpperCase()
	{
		$validation = new Strength();
		$validation->setRequirements(array_merge($this->noRules, ['upperCase' => TRUE]));

		$this->assertTrue($validation->isValid('ASasdf9DF'));
	}


	public function test_isValid_requireUpperCase_failWithoutUpperCase()
	{
		$validation = new Strength();
		$validation->setRequirements(array_merge($this->noRules, ['upperCase' => TRUE]));

		$this->assertFalse($validation->isValid('asdfff'));
	}


	public function test_isValid_requireLowerCase_passWithLowerCase()
	{
		$validation = new Strength();
		$validation->setRequirements(array_merge($this->noRules, ['lowerCase' => TRUE]));

		$this->assertTrue($validation->isValid('ASasdf9DF'));
	}


	public function test_isValid_requireLowerCase_failWithoutLowerCase()
	{
		$validation = new Strength();
		$validation->setRequirements(array_merge($this->noRules, ['lowerCase' => TRUE]));

		$this->assertFalse($validation->isValid('ASDD987'));
	}


	public function test_isValid_requireNumberCase_passWithNumberCase()
	{
		$validation = new Strength();
		$validation->setRequirements(array_merge($this->noRules, ['number' => TRUE]));

		$this->assertTrue($validation->isValid('ASasdf9DF'));
	}


	public function test_isValid_requireNumberCase_failWithoutNumberCase()
	{
		$validation = new Strength();
		$validation->setRequirements(array_merge($this->noRules, ['number' => TRUE]));

		$this->assertFalse($validation->isValid('ASDDasdf'));
	}


	/**
	 * @dataProvider providerSymbolPasswords
	 */
	public function test_isValid_requireSymbol_passWithSymbol($password)
	{
		$validation = new Strength();
		$validation->setRequirements(array_merge($this->noRules, ['specialSymbol' => FALSE]));

		$this->assertTrue($validation->isValid($password), 'Password "'.$password.'" did not met symbol requirement.');
	}


	public function test_isValid_requireSymbol_failWithoutSymbol()
	{
		$validation = new Strength();
		$validation->setRequirements(array_merge($this->noRules, ['specialSymbol' => TRUE]));

		$this->assertFalse($validation->isValid('ASDDasdf'));
	}


	/**
	 * @dataProvider providerCompareSimilarPasswords
	 */
	public function test_getStrengthScore_similarPassword_shouldReturnSameScore($pass1, $pass2)
	{
		$validation = new Strength();

		$score1 = $validation->getStrengthScore($pass1);
		$score2 = $validation->getStrengthScore($pass2);

		$this->assertSame($score1, $score2, 'Password "'.$pass1.'" strength is '.$score1.', password "'.$pass2.'" strength is '.$score2.', expected same.');
	}


	/**
	 * @dataProvider providerComparePasswords
	 */
	public function test_getStrengthScore_strongerPassword_shouldReturnHigherScore($weak, $strong)
	{
		$validation = new Strength();

		$weakScore = $validation->getStrengthScore($weak);
		$strongScore = $validation->getStrengthScore($strong);

		$this->assertTrue($weakScore < $strongScore, 'Password "'.$weak.'" strength is '.$weakScore.', password "'.$strong.'" strength is '.$strongScore.', expected higher.');
	}


	/**
	 * @dataProvider providerPasswordsStrength
	 */
	public function test_getStrength_password_shouldReturnExpectedStrength($password, $expectedStrength)
	{
		$validation = new Strength();

		$strength = $validation->getStrength($password);


		$this->assertEquals($expectedStrength, $strength, $validation->getStrengthScore($password));
	}


}
