<?php

namespace Bluesquare\ValidatorBundle;

use Bluesquare\ValidatorBundle\DependencyInjection\ValidatorExtension;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

class ValidatorBundle extends Bundle
{
    public function build(ContainerBuilder $container)
    {
        parent::build($container);
    }

    public function getContainerExtension()
    {
        if (null === $this->extension)
            $this->extension = new ValidatorExtension();
        return $this->extension;
    }
}
