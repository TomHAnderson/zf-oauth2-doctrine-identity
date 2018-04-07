<?php

namespace ZF\OAuth2\Doctrine\Identity;

use Zend\Permissions\Rbac\AbstractRole as AbstractRbacRole;
use Zend\Permissions\Acl\Acl;
use ZF\MvcAuth\Identity\IdentityInterface;
use ZF\MvcAuth\Authorization\AuthorizationInterface;
use Doctrine\Common\Persistence\ObjectManager;
use GianArb\Angry\Uninvokable;
use ZF\OAuth2\Doctrine\Identity\Exception;

class AuthenticatedIdentity extends AbstractRbacRole implements
    IdentityInterface
{
    use Uninvokable;

    protected $accessToken;
    protected $objectManager;
    protected $authorizationService;
    protected $name;

    public function __construct($accessToken, ObjectManager $objectManager, AuthorizationInterface $authorizationService, $name = 'doctrine')
    {
        $this->accessToken = $accessToken;
        $this->objectManager = $objectManager;
        $this->authorizationService = $authorizationService;
        $this->name = $name;
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

    public function setName($name) 
    {
        $this->name = $name;

        return $this;
    }

    public function getRoleId()
    {
        return $this->getName();
    }

    // For ZF\OAuth2\Provider\UserId\AuthenticationService
    public function getId()
    {
        return $this->getUser()->getId();
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

    public function getObjectManager()
    {
        return $this->objectManager;
    }
}
