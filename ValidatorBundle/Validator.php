<?php

namespace Bluesquare\ValidatorBundle;

use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Contracts\Translation\TranslatorInterface;

class Validator
{
    protected $request;
    protected $context;
    protected $errors;
    protected $entity;
    protected $values;
    protected $rules;
    protected $validated;
    protected $translator;

    public function __construct(RequestStack $requestStack, TranslatorInterface $translator)
    {
        $this->values = [];
        $this->errors = [];
        $this->rules = [];
        $this->validated = false;

        $this->translator = $translator;
        $this->request = $requestStack->getCurrentRequest();

        $session = $this->request->getSession()->getFlashBag()->get("Bluesquare:ValidatorBundle");

        if(is_array($session) && isset($session[0])) {
            if(isset($session[0]['context'])) $this->context = $session[0]['context'];
            if(isset($session[0]['errors']) && is_array($session[0]['errors'])) $this->errors = $session[0]['errors'];
            if(isset($session[0]['values']) && is_array($session[0]['values'])) $this->values = $session[0]['values'];
            $this->validated = true;
        }

        if ($this->post())
        {
            $values = [];
            foreach (array_merge($_GET, $_POST) as $field => $value) $values[$field] = $value;
            $json = @json_decode(file_get_contents('php://input'), true);
            if (is_array($json)) $values = array_merge($values, $json);
            $this->values = array_merge($this->values, $values);
        }
    }

    //

    public function context($context)
    {
        $this->context = $context;
        return $this;
    }

    public function entity($entity)
    {
        $this->entity = $entity;
        return $this;
    }

    public function set($key, $value)
    {
        $this->values[$key] = $value;
        return $this;
    }

    public function error($field, $error)
    {
        if (!isset($this->errors[$field]))
            $this->errors[$field] = [];

        $this->errors[$field][] = $error;

        return $this;
    }

    //

    public function json($code = 400, $data = [])
    {
        $data = array_merge([
            'message' => 'Please check your input',
            'error' => 'validator.form-error',
            'errors' => array_map(function ($errors) {
                return "validator.".$errors[0].(!is_null($this->context) ? ':'.$this->context : '');
            }, $this->errors)
        ], $data);

        return new JsonResponse($data, $code);
    }

    public function keep()
    {
        $data = [
            'errors' => $this->errors,
            'values' => $this->values,
            'context' => $this->context
        ];
        $this->request->getSession()->getFlashBag()->add('Bluesquare:ValidatorBundle', $data);
        return $this;
    }

    public function validated()
    {
        return $this->validated;
    }

    public function failed()
    {
        return (count($this->errors) > 0);
    }

    public function errors()
    {
        $translator = $this->translator;
        $context = $this->context;

        return array_map(function ($errors) use ($translator, $context) {
            $error = $errors[0];
            $message = null;
            if (!is_null($context)) {
                $message = $translator->trans("$context.$error", [], "validator");
            }
            if (is_null($message) || $message == "$context.$error") {
                $message = $translator->trans("$error", [], "validator");
            }
            return $message;
        }, $this->errors);
    }

    public function message()
    {
        $result = $this->failed() ? 'form_error' : 'form_success';
        $message = null;
        if (!is_null($this->context)) {
            $message = $this->translator->trans("$this->context.$result", [], "validator");
        }
        if (is_null($message) || $message == "$this->context.$result") {
            $message = $this->translator->trans("$result", [], "validator");
        }
        return $message;
    }

    public function has($field)
    {
        return !is_null($this->get($field));
    }

    public function value($field, $default = null)
    {
        $value = isset($this->values[$field]) ? trim($this->values[$field]) : $default;
        if (empty($value)) $value = $default;

        if (is_null($value) && !is_null($this->entity)) {
            $method = "get".$this->camelize($field);
            if (method_exists($this->entity, $method))
                $value = $this->entity->$method();
        }

        return $value;
    }

    public function get($field, $default = null)
    {
        $value = isset($this->values[$field]) ? trim($this->values[$field]) : $default;
        if (empty($value)) $value = $default;
        return $value;
    }

    public function checked($field)
    {
        return !is_null($this->get($field)) || $this->get($field) != '0' || $this->get($field) != 0;
    }

    public function getFile($name)
    {
        return $this->request->files->get($name);
    }

    public function hasFile($name)
    {
        $file = $this->getFile($name);
        return !is_null($file) && !(is_array($file) || $file instanceof Traversable);
    }

    public function hasFiles($name)
    {
        $files = $this->getFile($name);
        return !is_null($files) && (is_array($files) || $files instanceof Traversable);
    }

    public function inject()
    {
        $args = func_get_args();
        if (count($args) === 0) return false;
        if (is_object($args[0])) $entity = array_shift($args);
        else $entity = $this->entity;
        if (is_null($entity)) return false;

        foreach ($args as $field) {
            $method = "set".$this->camelize($field);
            if (method_exists($entity, $method)) $entity->$method($this->value($field));
        }

        return true;
    }

    //

    public function post()
    {
        return in_array(strtolower($this->request->getMethod()), ['delete', 'put', 'post', 'patch']);
    }

    public function check()
    {
        return $this->validate();
    }

    //

    protected function validate()
    {
        foreach ($this->rules as $field => $rules)
        {
            foreach ($rules as $rule) $this->test($field, $rule);
        }

        $this->validated = true;

        return (count($this->errors) == 0);
    }

    public function test($field, $rule)
    {
        $name = $rule['rule'];
        $data = $rule['data'];
        $value = $this->get($field);
        $success = true;

        switch ($name)
        {
            case 'required_file':
                $success = $this->hasFile($field);
                break;
            case 'required_files':
                $success = $this->hasFiles($field);
                break;
            case 'required':
                $success = !(is_null($value));
                break;
            case 'integer':
                $success = (filter_var($value, FILTER_VALIDATE_INT) ? true : false);
                break;
            case 'float':
                $success = (filter_var($value, FILTER_VALIDATE_FLOAT) ? true : false);
                break;
            case 'boolean':
                $success = (filter_var($value, FILTER_VALIDATE_BOOLEAN) ? true : false);
                break;
            case 'email':
                $success = (filter_var($value, FILTER_VALIDATE_EMAIL) ? true : false);
                break;
            case 'phone':
                $_pattern = "/^\+?\d{7,15}$/";
                $success = (!(strlen($value) == 10 && ctype_digit($value)) && !preg_match($_pattern, $value)) ? false : true;
                break;
            case 'zipcode':
                $success = (!(strlen($value) == 5 && ctype_digit($value))) ? false : true;
                break;
            case 'alphanumeric':
                $success = ctype_alnum($value);
                break;
            case 'date':
                $success = preg_match('/^([0-9]{2}\/[0-9]{2}\/[0-9]{4})|([0-9]{4}-[0-9]{2}-[0-9]{2})$/', $value);
                break;
            case 'datetime':
                $_pattern = "[0-9]{4}\-[0-9]{2}\-[0-9]{2}\ [0-9]{1,2}\:[0-9]{1,2}\:[0-9]{1,2}";
                $success = (preg_matchs($_pattern, $value)) ? true : false;
                break;
            case 'url':
                $_pattern = "%^((?:(?:https?|ftp)://))?(?:\S+(?::\S*)?@)?(?:(?!(?:10|127)(?:\.\d{1,3}){3})(?!(?:169\.254|192\.168)(?:\.\d{1,3}){2})(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z\x{00a1}-\x{ffff}0-9]-*)*[a-z\x{00a1}-\x{ffff}0-9]+)(?:\.(?:[a-z\x{00a1}-\x{ffff}0-9]-*)*[a-z\x{00a1}-\x{ffff}0-9]+)*(?:\.(?:[a-z\x{00a1}-\x{ffff}]{2,}))\.?)(?::\d{2,5})?(?:[/?#]\S*)?$%iuS";
                $success = preg_match($_pattern, $value);
                break;
            case 'in_array':
                $success = in_array($value, $data['values']);
                break;
            case 'min':
                $success = min($value, $data['length']) == $value ? true : false;
                break;
            case 'max':
                $success = max($value, $data['length']) == $value ? true : false;
                break;
            case 'min_length':
                $success = strlen($value) >= $data['length'] ? true : false;
                break;
            case 'max_length':
                $success = strlen($value) <= $data['length'] ? true : false;
                break;
            case 'identical':
                $success = $value == $this->get($data['target']);
                break;
            // (éwé c'est un switch)
        }

        if (!$success) {
            $this->error($field, $name);
        }

        return $success;
    }

    public function rule($field, $rule, $data = [])
    {
        if (!isset($this->rules[$field]))
            $this->rules[$field] = [];

        $this->rules[$field][] = ['rule' => $rule, 'data' => $data];

        return $this;
    }

    // Rules: multiple

    public function required()
    {
        foreach (func_get_args() as $field) $this->rule($field, 'required');
        return $this;
    }

    public function integer()
    {
        foreach (func_get_args() as $field) $this->rule($field, 'integer');
        return $this;
    }

    public function float()
    {
        foreach (func_get_args() as $field) $this->rule($field, 'float');
        return $this;
    }

    public function boolean()
    {
        foreach (func_get_args() as $field) $this->rule($field, 'boolean');
        return $this;
    }

    public function email()
    {
        foreach (func_get_args() as $field) $this->rule($field, 'email');
        return $this;
    }

    public function phone()
    {
        foreach (func_get_args() as $field) $this->rule($field, 'phone');
        return $this;
    }

    public function zipcode()
    {
        foreach (func_get_args() as $field) $this->rule($field, 'zipcode');
        return $this;
    }

    public function alphanumeric()
    {
        foreach (func_get_args() as $field) $this->rule($field, 'alphanumeric');
        return $this;
    }

    public function date()
    {
        foreach (func_get_args() as $field) $this->rule($field, 'date');
        return $this;
    }

    public function datetime()
    {
        foreach (func_get_args() as $field) $this->rule($field, 'datetime');
        return $this;
    }

    public function url()
    {
        foreach (func_get_args() as $field) $this->rule($field, 'url');
        return $this;
    }

    // Rules: single

    public function requiredFile($name)
    {
        $this->rule($name, 'required_file');
        return $this;
    }

    public function requiredFiles($name)
    {
        $this->rule($name, 'required_files');
        return $this;
    }

    public function min($field, $length)
    {
        $this->rule($field, 'min', ['length' => $length]);
        return $this;
    }

    public function max($field, $length)
    {
        $this->rule($field, 'max', ['length' => $length]);
        return $this;
    }

    public function minLength($field, $length)
    {
        $this->rule($field, 'min_length', ['length' => $length]);
        return $this;
    }

    public function maxLength($field, $length)
    {
        $this->rule($field, 'max_length', ['length' => $length]);
        return $this;
    }

    public function inArray($field, $values)
    {
        $this->rule($field, 'in_array', ['values' => $values]);
        return $this;
    }

    public function identical($field, $field_confirm)
    {
        $this->rule($field_confirm, 'identical', ['target' => $field]);
        return $this;
    }

    // Helpers

    protected function camelize($string)
    {
        $string = implode('_', explode('-', $string));
        $words = array_map('ucfirst', explode('_', $string));
        return implode('', $words);
    }
}
