<?php
namespace AppBundle\Security;

use AppBundle\Security\User;
use Psr\Container\ContainerInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Filesystem\Exception\IOException;

class UserProvider implements UserProviderInterface
{
	private $serializer;
	private $datafile;

	public function __construct(ContainerInterface $container)
	{
		if ($container->hasParameter('datafile')) {
			$this->datafile = $container->getParameter('datafile');
			if (file_exists($this->datafile)) {
				$this->serializer = $container->get('serializer');
			} else {
				throw new IOException(
					sprintf('Datafile "%s" is not exists', $this->datafile)
				);
			}
		} else {
			throw new IOException('Datafile is not set');
		}
	}

	public function loadUserByUsername($username)
	{
		$data = $this->serializer->decode(file_get_contents($this->datafile), 'csv');
		if (!empty($data)) {
			$user = false;
			foreach (array_column($data, 'username') as $id => $_username) {
				if ($username === $_username) {
					$user = new User(
						$data[$id]['username'],
						$data[$id]['password'],
						$data[$id]['salt'],
						$data[$id]['roles']
					);
					break;
				}
			}
			if ($user) {
				return $user;
			}
		}
		throw new UsernameNotFoundException(
			sprintf('Username "%s" does not exist.', $username)
		);
	}

	public function refreshUser(UserInterface $user)
	{
		if (!$user instanceof User) {
			throw new UnsupportedUserException(
				sprintf('Instances of "%s" are not supported.', get_class($user))
			);
		}
		return $this->loadUserByUsername($user->getUsername());
	}

	public function supportsClass($class)
	{
		return (User::class === $class);
	}
}