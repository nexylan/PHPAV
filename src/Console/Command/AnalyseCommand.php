<?php


namespace Nexy\PHPAV\Console\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Finder\Finder;
use Symfony\Component\Finder\Glob;
use Symfony\Component\Finder\SplFileInfo;

/**
 * @author Sullivan Senechal <soullivaneuh@gmail.com>
 */
final class AnalyseCommand extends Command
{
    /**
     * {@inheritdoc}
     */
    protected function configure()
    {
        parent::configure();

        $this
            ->setName('analyse')
            ->setDescription('Analyses given files and folder to find any viruses and intrusions.')
            ->addArgument('paths', InputArgument::REQUIRED | InputArgument::IS_ARRAY)
        ;
    }

    /**
     * {@inheritdoc}
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $files = $this->getFilesToAnalyse(array_unique($input->getArgument('paths')));

        return 0;
    }

    /**
     * @param string[] $paths
     *
     * @return string[]
     */
    private function getFilesToAnalyse($paths)
    {
        $files = [];

        foreach ($paths as $path) {
            if (is_dir($path)) {
                $files = array_merge($files, array_keys(iterator_to_array(Finder::create()->files()->name('*.php')->in($path))));
            } elseif ('php' === pathinfo($path, PATHINFO_EXTENSION)) {
                $files = array_merge($files, [$path]);
            }
        }

        return $files;
    }
}
