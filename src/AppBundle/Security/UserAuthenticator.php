<?php
namespace AppBundle\Security;

use Psr\Container\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Core\Exception\InvalidCsrfTokenException;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

class UserAuthenticator extends AbstractGuardAuthenticator
{
	use TargetPathTrait;

	private $loginUrl;
    private $defaultSuccessRedirectUrl;
    private $csrfTokenManager;
    private $container;

    public function __construct(ContainerInterface $container, CsrfTokenManagerInterface $csrfTokenManager)
    {
    	$this->csrfTokenManager = $csrfTokenManager;
    	$this->loginUrl = $container->get('router')->generate('login');
    	$this->defaultSuccessRedirectUrl = $container->get('router')->generate('homepage');
    	$this->container = $container;
    }

	public function getLoginUrl()
	{
		return $this->loginUrl;
	}

	protected function getDefaultSuccessRedirectUrl()
    {
        return $this->defaultSuccessRedirectUrl;
    }

	public function getCredentials(Request $request)
	{
		/*$csrfToken = $request->request->has('_csrf_token');
		var_dump($csrfToken,$this->csrfTokenManager->isTokenValid(new CsrfToken('authenticate', $csrfToken)));
		if ($this->csrfTokenManager->isTokenValid(new CsrfToken('authenticate', $csrfToken)) === false) {
			return;//throw new InvalidCsrfTokenException('Invalid CSRF token.');
        }*/
		if ($request->request->has('_username') && !$this->checkForBadAuth($request)) {
			return [
				'username' => $request->request->get('_username'),
				'password' => $request->request->get('_password'),
			];
		} else {
			return;
		}
	}

	public function getUser($credentials, UserProviderInterface $userProvider)
	{
		if (isset($credentials['username'])) {
			return $userProvider->loadUserByUsername($credentials['username']);
		} else {
			return;
		}
	}

	public function checkCredentials($credentials, UserInterface $user)
	{
		if (isset($credentials['password'])) {
			$encoderFactory = $this->container->get('security.encoder_factory');
			$encoder = $encoderFactory->getEncoder($user);
			return $encoder->isPasswordValid($user->getPassword(), $credentials['password'], $user->getSalt());
		} else {
			return;
		}
	}

	public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
	{
		$targetPath = null;
		if ($request->getSession() instanceof SessionInterface) {
			$targetPath = $this->getTargetPath($request->getSession(), $providerKey);
		}
		if (!$targetPath) {
			$targetPath = $this->getDefaultSuccessRedirectUrl();
		}
		return new RedirectResponse($targetPath);
	}

	public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
	{
		if ($request->getSession() instanceof SessionInterface) {
			$request->getSession()->set(Security::AUTHENTICATION_ERROR, $exception);
			$badAuth = $request->getSession()->get('bad_auth');
			if ($badAuth === null) {
				$badAuth = ['tries' => 1, 'time' => new \DateTime('now')];
			} elseif ($badAuth['tries'] < 3) {
				$badAuth['tries'] += 1;
				$badAuth['time'] = new \DateTime('now');
			}
			$request->getSession()->set('bad_auth', $badAuth);
        }
        $url = $this->getLoginUrl();
        return new RedirectResponse($url);
	}

	protected function checkForBadAuth(Request $request)
	{
		$badAuth = $request->getSession()->get('bad_auth');
		if (isset($badAuth['tries']) && $badAuth['tries'] >= 3) {
			$lastTime = $badAuth['time'];
			$now = new \DateTime('now');
			$diff = doubleval($now->diff($lastTime)->format('%i.%s'));
			if ($diff > 5) {
				$request->getSession()->set('bad_auth', null);
				if ($request->getSession()->has('badAuth')) {
					$request->getSession()->remove('badAuth');
				}
				return false;
			} else {
				$seconds = explode('.', $diff);
				$seconds[0] *= 60;
				$seconds = (300 - array_sum($seconds));
				$request->getSession()->set('badAuth', sprintf(
					'Locked, please try again in %s seconds',
					$seconds
				));
				return true;
			}
		} else {
			if ($request->getSession()->has('badAuth')) {
				$request->getSession()->remove('badAuth');
			}
			return false;
		}
	}

	public function start(Request $request, AuthenticationException $authException = null)
	{
		$url = $this->getLoginUrl();
        return new RedirectResponse($url);
	}

	public function supportsRememberMe()
	{
		return false;
	}
}