<?php

namespace GuzzleMiddleware;

class AliyunSMS
{
    public function __construct(protected string $accessKeyId, protected string $accessKeySecret) {}

    public function __invoke($handler)
    {
        return function ($request, $options) use ($handler) {
            $params = [
                'AccessKeyId' => $this->accessKeyId,
                'Format' => 'JSON',
                'SignatureMethod' => 'HMAC-SHA1',
                'SignatureVersion' => '1.0',
                'SignatureNonce' => uniqid(),
                'Timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
                'Action' => 'SendSms',
                'Version' => '2017-05-25',
            ];

            parse_str($request->getUri()->getQuery(), $query);

            $params = array_merge($params, $query);
            $params['Signature'] = $this->generateSign($params);

            $request = $request->withUri($request->getUri()->withQuery(http_build_query($params)));

            return $handler($request, $options);
        };
    }

    protected function generateSign($params)
    {
        ksort($params);
        $stringToSign = 'GET&%2F&'.urlencode(http_build_query($params, null, '&', PHP_QUERY_RFC3986));

        return base64_encode(hash_hmac('sha1', $stringToSign, $this->accessKeySecret.'&', true));
    }
}
