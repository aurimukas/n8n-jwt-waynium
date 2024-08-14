import type {
	IDataObject,
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';
import { NodeOperationError } from 'n8n-workflow';

import jwt from 'jsonwebtoken';

import { formatPrivateKey } from 'n8n-nodes-base/dist/utils/utilities';
import { parseJsonParameter } from 'n8n-nodes-base/dist/nodes/Set/v2/helpers/utils';

interface JwtHeaderWaynium extends jwt.JwtHeader {
	apiKey?: string | undefined;
}

const prettifyOperation = (operation: string) => {
	if (operation === 'sign') {
		return 'Sign a JWT';
	}

	return operation;
};

export class JwtWaynium implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'JWTWaynium',
		name: 'jwtwaynium',
		icon: 'file:jwtwaynium.svg',
		group: ['transform'],
		version: 1,
		description: 'JWT-Waynium adapted to work with Waynium API which is using custom',
		subtitle: `={{(${prettifyOperation})($parameter.operation)}}`,
		defaults: {
			name: 'JWTWaynium',
		},
		inputs: ['main'],
		outputs: ['main'],
		credentials: [
			{
				// eslint-disable-next-line n8n-nodes-base/node-class-description-credentials-name-unsuffixed
				name: 'jwtAuth',
				required: true,
			},
		],
		properties: [
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Sign',
						value: 'sign',
						action: 'Sign a JWT',
					},
				],
				default: 'sign',
			},
			{
				displayName: 'Use JSON to Build Payload',
				name: 'useJson',
				type: 'boolean',
				default: false,
				description: 'Whether to use JSON to build the claims',
				displayOptions: {
					show: {
						operation: ['sign'],
					},
				},
			},
			{
				displayName: 'Payload Claims',
				name: 'claims',
				type: 'collection',
				placeholder: 'Add Claim',
				default: {},
				options: [
					{
						displayName: 'Audience',
						name: 'audience',
						type: 'string',
						placeholder: 'e.g. https://example.com',
						default: '',
						description: 'Identifies the recipients that the JWT is intended for',
					},
					{
						displayName: 'Expires In',
						name: 'expiresIn',
						type: 'number',
						placeholder: 'e.g. 3600',
						default: 3600,
						description: 'The lifetime of the token in seconds',
						typeOptions: {
							minValue: 0,
						},
					},
					{
						displayName: 'Issuer',
						name: 'issuer',
						type: 'string',
						placeholder: 'e.g. https://example.com',
						default: '',
						description: 'Identifies the principal that issued the JWT',
					},
					{
						displayName: 'JWT ID',
						name: 'jwtid',
						type: 'string',
						placeholder: 'e.g. 123456',
						default: '',
						description: 'Unique identifier for the JWT',
					},
					{
						displayName: 'Not Before',
						name: 'notBefore',
						type: 'number',
						default: 0,
						description: 'The time before which the JWT must not be accepted for processing',
						typeOptions: {
							minValue: 0,
						},
					},
					{
						displayName: 'Subject',
						name: 'subject',
						type: 'string',
						default: '',
						description: 'Identifies the principal that is the subject of the JWT',
					},
				],
				displayOptions: {
					show: {
						operation: ['sign'],
						useJson: [true],
					},
				},
			},
			{
				displayName: 'Payload Claims (JSON)',
				name: 'claimsJson',
				type: 'json',
				description: 'Claims to add to the token in JSON format',
				default: '{\n  "my_field_1": "value 1",\n  "my_field_2": "value 2"\n}\n',
				validateType: 'object',
				ignoreValidationDuringExecution: true,
				typeOptions: {
					rows: 5,
				},
				displayOptions: {
					show: {
						operation: ['sign'],
						useJson: [true],
					},
				},
			},
			{
				displayName: 'Options',
				name: 'options',
				type: 'collection',
				placeholder: 'Add option',
				default: {},
				options: [
					{
						displayName: 'Key ID',
						name: 'kid',
						type: 'string',
						placeholder: 'e.g. 123456',
						default: '',
						description:
							'The kid (key ID) claim is an optional header claim, used to specify the key for validating the signature',
						displayOptions: {
							show: {
								'/operation': ['sign'],
							},
						},
					},
					{
						displayName: 'API Key',
						name: 'apiKey',
						type: 'string',
						typeOptions: {
							password: true,
						},
						placeholder: 'e.g. 123456',
						default: '',
						description:
							'The API Key (apiKey) claim is an optional header claim, used to specify the key for validating the signature',
						displayOptions: {
							show: {
								'/operation': ['sign'],
							},
						},
					},
					{
						displayName: 'Override Algorithm',
						name: 'algorithm',
						type: 'options',
						options: [
							{
								name: 'ES256',
								value: 'ES256',
							},
							{
								name: 'ES384',
								value: 'ES384',
							},
							{
								name: 'ES512',
								value: 'ES512',
							},
							{
								name: 'HS256',
								value: 'HS256',
							},
							{
								name: 'HS384',
								value: 'HS384',
							},
							{
								name: 'HS512',
								value: 'HS512',
							},
							{
								name: 'PS256',
								value: 'PS256',
							},
							{
								name: 'PS384',
								value: 'PS384',
							},
							{
								name: 'PS512',
								value: 'PS512',
							},
							{
								name: 'RS256',
								value: 'RS256',
							},
							{
								name: 'RS384',
								value: 'RS384',
							},
							{
								name: 'RS512',
								value: 'RS512',
							},
						],
						default: 'HS256',
						description:
							'The algorithm to use for signing or verifying the token, overrides algorithm in credentials',
						displayOptions: {
							show: {
								'/operation': ['sign'],
							},
						},
					},
				],
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];

		const operation = this.getNodeParameter('operation', 0);

		const credentials = (await this.getCredentials('jwtAuth')) as {
			keyType: 'passphrase' | 'pemKey';
			publicKey: string;
			privateKey: string;
			secret: string;
			algorithm: jwt.Algorithm;
		};

		for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
			const options = this.getNodeParameter('options', itemIndex, {}) as {
				algorithm?: jwt.Algorithm;
				complete?: boolean;
				ignoreExpiration?: boolean;
				ignoreNotBefore?: boolean;
				clockTolerance?: number;
				kid?: string;
				apiKey?: string;
			};

			try {
				if (operation === 'sign') {
					const useJson = this.getNodeParameter('useJson', itemIndex) as boolean;

					let payload: IDataObject = {};

					if (useJson) {
						payload = parseJsonParameter(
							this.getNodeParameter('claimsJson', itemIndex) as IDataObject,
							this.getNode(),
							itemIndex,
						);
					} else {
						payload = this.getNodeParameter('claims', itemIndex) as IDataObject;
					}

					let secretOrPrivateKey;

					if (credentials.keyType === 'passphrase') {
						secretOrPrivateKey = credentials.secret;
					} else {
						secretOrPrivateKey = formatPrivateKey(credentials.privateKey);
					}

					const signingOptions: jwt.SignOptions = {
						algorithm: options.algorithm ?? credentials.algorithm,
					};
					if (options.kid) signingOptions.keyid = options.kid;

					if (options.apiKey) {
						let header: JwtHeaderWaynium = {
							alg: options.algorithm ?? credentials.algorithm,
							apiKey: options.apiKey,
						};
						signingOptions.header = header;
					}

					const token = jwt.sign(payload, secretOrPrivateKey, signingOptions);

					returnData.push({
						json: { token },
						pairedItem: itemIndex,
					});
				}
			} catch (error) {
				if (error.message === 'invalid signature') {
					error = new NodeOperationError(this.getNode(), "The JWT token can't be verified", {
						itemIndex,
						description:
							'Be sure that the provided JWT token is correctly encoded and matches the selected credentials',
					});
				}
				if (this.continueOnFail(error)) {
					returnData.push({
						json: this.getInputData(itemIndex)[0].json,
						error,
						pairedItem: itemIndex,
					});
					continue;
				}
				if (error.context) {
					error.context.itemIndex = itemIndex;
					throw error;
				}
				throw new NodeOperationError(this.getNode(), error, {
					itemIndex,
				});
			}
		}

		return [returnData];
	}
}
