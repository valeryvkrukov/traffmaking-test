<?php
namespace AppBundle\Controller;

use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

class SecurityController extends Controller
{
	/**
	 * @Route("/login", name="login")
	 */
	public function loginAction(Request $request, AuthenticationUtils $authUtils)
	{
		if ($this->get('security.authorization_checker')->isGranted('IS_AUTHENTICATED_FULLY')) {
			return $this->redirectToRoute('homepage');
		}
		$error = $authUtils->getLastAuthenticationError();
		$lastUsername = $authUtils->getLastUsername();
		return $this->render('security/login.html.twig', [
			'last_username' => $lastUsername,
			'error' => $error,
		]);
	}
}