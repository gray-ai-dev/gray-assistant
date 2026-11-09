import { useState } from 'react';
import { useDropzone } from 'react-dropzone';
import { Field as BaseField } from '@cloudflare/kumo/primitives/field';
import { UploadSimple, X } from '../components/icons';
import { Button, IconButton } from './Button';
import './file.css';

/**
 * One file, chosen from the system dialog or dropped on the field. react-dropzone owns the drag state, the dialog and
 * the check of each file against `accept`; a file of another type is refused with a sentence, never taken silently.
 * The page holds the file (`file`, `onFileChange`) and shows what it knows about it, e.g. its size in the `Field` hint.
 */
export function FileInput({ accept, file, onFileChange, disabled }: {
  /** MIME types as the `accept` attribute lists them, e.g. "audio/*,video/mp4". */
  accept?: string;
  file: File | null;
  onFileChange(file: File | null): void;
  disabled?: boolean;
}) {
  const [refused, setRefused] = useState('');
  const { getRootProps, getInputProps, open, isDragActive, isDragReject } = useDropzone({
    accept: accept ? Object.fromEntries(accept.split(',').map(type => [type.trim(), []])) : undefined,
    multiple: false, disabled, noClick: true, noKeyboard: true,
    onDropAccepted: files => { setRefused(''); onFileChange(files[0] ?? null); },
    onDropRejected: rejections => setRefused(rejections.length > 1 ? 'Choose one file.' : 'This file type cannot be used here.'),
  });
  return <div {...getRootProps({ className: 'ui-file', 'data-drag': isDragActive ? (isDragReject ? 'reject' : 'accept') : undefined, 'data-disabled': disabled || undefined })}>
    <BaseField.Control render={<input {...getInputProps()} />} />
    <Button onClick={open} disabled={disabled} icon={<UploadSimple size={15} aria-hidden="true" />}>{file ? 'Replace file' : 'Choose file'}</Button>
    <span className="ui-file__text">{file ? file.name : 'or drop it here'}</span>
    {file && <IconButton size="sm" label="Remove file" disabled={disabled} icon={<X size={15} aria-hidden="true" />} onClick={() => { setRefused(''); onFileChange(null); }} />}
    {refused && <p className="ui-file__refused" role="alert">{refused}</p>}
  </div>;
}
