<?php

namespace Pagewiser\Security\Password;

class Strength
{

	const WEAK = 1;
	const AVERAGE = 2;
	const STRONG = 3;
	const SECURE = 4;

	private $symbols = '`~!@#$%^&*()_-+={}|[]\\;\':",./<>?';

	private $combinations = [
		'upperCase' => 26,
		'lowerCase' => 26,
		'number' => 10,
		'symbol' => 33,
	];

	private $requirements = [
		'upperCase' => TRUE,
		'lowerCase' => TRUE,
		'number' => TRUE,
		'specialSymbol' => TRUE,
		'minLength' => 6,
		'maxLength' => NULL,
	];

	private $bonus = [
		'excess' => 1,
		'upperCase' => 3,
		'lowerCase' => 3,
		'number' => 3,
		'symbol' => 4,
		'specialSymbol' => 5,
	];

	private $strength = [
		1 => 50,
		2 => 250,
		3 => 300,
		4 => NULL,
	];

	private $lastErrors = [];

	public $lastScore = [];


	public function setRequirements(array $options)
	{
		$this->requirements = array_merge($this->requirements, $options);
	}


	public function isValid($password, array $vagueBlacklist = [])
	{
		$this->lastErrors = [];

		if ($this->requirements['minLength'] > 0 && mb_strlen($password) < $this->requirements['minLength'])
		{
			return FALSE;
		}

		if ($this->requirements['maxLength'] > 0 && mb_strlen($password) > $this->requirements['maxLength'])
		{
			return FALSE;
		}

		if ($this->requirements['upperCase'] == TRUE && !$this->validateUpperCase($password))
		{
			return FALSE;
		}

		if ($this->requirements['lowerCase'] == TRUE && !$this->validateLowerCase($password))
		{
			return FALSE;
		}

		if ($this->requirements['number'] == TRUE && !$this->validateNumber($password))
		{
			return FALSE;
		}

		if ($this->requirements['specialSymbol'] == TRUE && !$this->validateSpecialSymbol($password))
		{
			return FALSE;
		}

		return TRUE;
	}


	public function getStrength($password, array $vagueBlacklist = [])
	{
		$score = $this->getStrengthScore($password, $vagueBlacklist);

		foreach ($this->strength as $key => $value)
		{
			if ($score <= $value || is_null($value))
			{
				return $key;
			}
		}
	}


	public function getStrengthScore($password, array $vagueBlacklist = [])
	{
		$score = $this->getScore($password, $vagueBlacklist);

		$baseScore = (min(25, $score['excess'] * 10)) // base
			+ ($score['excess'] * $this->bonus['excess'])
			+ ($score['uppers'] * $this->bonus['upperCase'])
			+ ($score['lowers'] * $this->bonus['lowerCase'])
			+ ($score['numbers'] * $this->bonus['number'])
			+ ($score['symbols'] * $this->bonus['specialSymbol'])
			+ $score['combo'];

		$bruteForceMinutes = bcdiv($this->getCombinations($score, mb_strlen($password)), '2000000000', 2);

		$bruteForceIndex = 1;
		if ($bruteForceMinutes < 100)
		{
			$bruteForceIndex = 0.5;
		}
		elseif ($bruteForceMinutes < 1000)
		{
			$bruteForceIndex = 1;
		}
		elseif ($bruteForceMinutes < 10000)
		{
			$bruteForceIndex = 1.5;
		}
		elseif ($bruteForceMinutes < 100000)
		{
			$bruteForceIndex = 2;
		}
		else
		{
			$bruteForceIndex = 3;
		}


		return $baseScore * $bruteForceIndex;
	}


	protected function getScore($password, array $vagueBlacklist = [])
	{
		$password = (string) $password;
		$score = [
			'uppers' => 0, 
			'lowers' => 0,
			'numbers' => 0,
			'symbols' => 0,
			'specialSymbols' => 0,
			'excess' => 0,
			'combo' => 0,
			'flatLower' => 0,
			'flatNumber' => 0,
		];

		if (preg_match_all('/[A-Z]+?/', $password, $matches))
		{
			$score['uppers'] = count($matches[0]);
		}

		if (preg_match_all('/[a-z]+?/', $password, $matches))
		{
			$score['lowers'] = count($matches[0]);
		}

		if (preg_match_all('/[0-9]+?/', $password, $matches))
		{
			$score['numbers'] = count($matches[0]);
		}

		if (preg_match_all('/[^a-zA-Z0-9]+?/', $password, $matches))
		{
			$score['symbols'] = count($matches[0]);
		}

		$score['excess'] = max(0, mb_strlen($password) - max(6, $this->requirements['minLength']));

		$combinations = (int) ($score['uppers'] > 0) + (int) ($score['lowers'] > 0) + (int) ($score['numbers'] > 0) + (int) ($score['symbols'] > 0);
		$score['combo'] = ($combinations - 1) * 10;

		$this->lastScore = $score;

		return $score;
	}


	protected function getCombinations($score, $length)
	{
		$combinations =
			(min($score['uppers'], 1) * $this->combinations['upperCase'])
			+ (min($score['lowers'], 1) * $this->combinations['lowerCase'])
			+ (min($score['numbers'], 1) * $this->combinations['number'])
			+ (min($score['symbols'], 1) * $this->combinations['symbol']);

		return bcpow($combinations, $length);
	}


	protected function validateUpperCase($value)
	{
		return preg_match('/[A-Z]/', $value);
	}


	protected function validateLowerCase($value)
	{
		return preg_match('/[a-z]/', $value);
	}


	protected function validateNumber($value)
	{
		return preg_match('/[0-9]/', $value);
	}


	protected function validateSpecialSymbol($value)
	{
		return preg_match('/[^0-9a-zA-Z]/', $value);
	}


}
