<?php

namespace ZF\OAuth2\Doctrine\Identity;

use ZF\MvcAuth\Identity\IdentityInterface;
use ZF\MvcAuth\Authorization\AuthorizationInterface;
use Zend\Permissions\Rbac\AbstractRole as AbstractRbacRole;
use Zend\Permissions\Acl\Acl;
use ZF\OAuth2\Doctrine\Identity\Exception;
use GianArb\Angry\Uninvokable;

class AuthenticatedIdentity extends AbstractRbacRole implements
    IdentityInterface
{
    use Uninvokable;

    protected $accessToken;
    protected $authorizationService;
    protected $name = 'doctrine';

    public function __construct($accessToken, AuthorizationInterface $authorizationService)
    {
        $this->accessToken = $accessToken;
        $this->authorizationService = $authorizationService;
    }

    public function getAuthenticationIdentity()
    {
        return [
            'user' => $this->getUser(),
            'client' => $this->getClient(),
            'accessToken' => $this->getAccessToken(),
        ];
    }

    public function getAuthorizationService()
    {
        return $this->authorizationService;
    }

    public function isAuthorized($resource, $privilege)
    {
        if ($this->authorizationService instanceof Acl) {
            return $this->authorizationService->isAuthorized($this, $resource, $privilege);
        } else {
            throw new Exception('isAuthorized is for ACL only.');
        }
    }

    public function getRoleId()
    {
        return $this->getName();
    }

    public function getUser()
    {
        return $this->accessToken->getUser();
    }

    public function getClient()
    {
        return $this->accessToken->getClient();
    }

    public function getAccessToken()
    {
        return $this->accessToken;
    }
}
