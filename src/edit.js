/**
 * Retrieves the translation of text.
 *
 * @see https://developer.wordpress.org/block-editor/reference-guides/packages/packages-i18n/
 */
import { __ } from '@wordpress/i18n';

/**
 * React hook that is used to mark the block wrapper element.
 * It provides all the necessary props like the class name.
 *
 * @see https://developer.wordpress.org/block-editor/reference-guides/packages/packages-block-editor/#useblockprops
 */
import { useBlockProps, InspectorControls } from '@wordpress/block-editor';

/**
 * WordPress components
 */
import { 
	PanelBody,
	Button,
	Card,
	CardHeader,
	CardBody,
	ExternalLink
} from '@wordpress/components';

/**
 * Lets webpack process CSS, SASS or SCSS files referenced in JavaScript files.
 * Those files can contain any CSS code that gets applied to the editor.
 *
 * @see https://www.npmjs.com/package/@wordpress/scripts#using-css
 */
import './editor.scss';

/**
 * Simple backend placeholder component that directs users to frontend
 */
export default function Edit() {
	return (
		<>
			<InspectorControls>
				<PanelBody title={__('More Blocks by iconick', 'wordpress-readme-generator-block-wp')} initialOpen={false}>
					<p>{__('Think these ideas are wild? You ain\'t seen nothing yet.', 'wordpress-readme-generator-block-wp')}</p>
					<ExternalLink href="https://iconick.io/blocks/">
						{__('Click to enter the block wonderland', 'wordpress-readme-generator-block-wp')}
					</ExternalLink>
				</PanelBody>
			</InspectorControls>
			
			<div {...useBlockProps()}>
				<Card>
					<CardHeader>
						<h2>{__('WordPress Readme Generator', 'wordpress-readme-generator-block-wp')}</h2>
					</CardHeader>
					<CardBody>
						<div className="backend-placeholder">
							<span className="icon">📝</span>
							<h3>{__('Frontend Magic Awaits!', 'wordpress-readme-generator-block-wp')}</h3>
							<p>
								{__('The WordPress Readme Generator works its magic on the frontend where visitors can create perfect readme.txt files with visual formatting, interactive forms, and real-time preview capabilities.', 'wordpress-readme-generator-block-wp')}
							</p>
							<p>
								<strong>{__('View your published page to access the full generator!', 'wordpress-readme-generator-block-wp')}</strong>
							</p>
							<Button 
								isPrimary
								href="#"
								onClick={(e) => {
									e.preventDefault();
									window.open(window.location.href.replace('/wp-admin/', '/'), '_blank');
								}}
							>
								{__('Preview on Frontend', 'wordpress-readme-generator-block-wp')}
							</Button>
						</div>
					</CardBody>
				</Card>
			</div>
		</>
	);
}