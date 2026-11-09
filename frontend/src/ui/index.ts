// Gray design system. Pages import components from here and pass data; they
// do not hand-roll buttons, inputs, tables, notices or code blocks. Rules and
// usage: DESIGN.md (Components) and src/ui/README.md.
import './ui.css';

export { Button, LinkButton, IconButton, buttonClass, type ButtonProps, type ButtonVariant, type ButtonSize } from './Button';
export { Field, TextInput, NumberInput, SearchInput, TextArea, type FieldProps } from './Field';
export { FileInput } from './File';
export { Slider } from './Slider';
export { DateTimeField } from './DateTimeField';
export { formatCount, formatShort, formatMoneyShort } from './number';
export { Checkbox, Switch } from './Choice';
export { SelectField } from './SelectField';
export { SegmentedControl, Tabs, type SegmentOption, type TabItem } from './Segmented';
export { Page, PageHeader, Section, SectionHeader, Panel, Stack, Inline, Grow, FormGrid, Split } from './Layout';
export { Notice, EmptyState, Badge, Spinner, Skeleton, type Tone } from './Feedback';
export { DescriptionList, DescriptionItem, Stat, StatGroup, type StatDelta, Table, TableHead, TableBody, TableRow, TableHeaderCell, TableCell, Disclosure, List, Steps, Step, type StepState, Progress } from './Data';
export { Text, TextLink, InlineCode, VisuallyHidden, useTruncated } from './Text';
export { CodeBlock, CodeExamples, CopyButton, type CodeLanguage, type CodeExample } from './Code';
export { Fieldset } from './Fieldset';
export { SettingsList, SettingsRow } from './Settings';
export { StackedTable } from './StackedTable';
export { MultiSelectField, type MultiSelectOption } from './MultiSelectField';
export { Picker, type PickerChoice } from './Picker';
export { focusHeading } from './focus';
export { SortableHeaderCell, RowHeaderCell, type SortDirection } from './TableHeaders';
export { Menu, MenuItem, MenuSeparator } from './Menu';
export { OverflowNav, type NavLink } from './OverflowNav';
export { SectionNav } from './SectionNav';
export { AutocompleteInput, type Suggestion } from './Autocomplete';
export { TimeChart, type ChartSeries, type ChartPoint } from './Chart';
export { Breakdown, type BreakdownItem } from './Breakdown';
export { Sparkline } from './Sparkline';
export { Meter } from './Meter';
export { Tape, type TapeCell, type TapeTone } from './Tape';
export { StatusStrip, StatusLegend, RoundTiles, StatusGlyph, WeightBar, type StatusTone, type StatusStripCell, type RoundMark } from './StatusStrip';
export { Tooltip } from './Tooltip';
export { InfoTip } from './InfoTip';
export { FixedLayer, usePopupPositionMethod } from './popup';
export { UiProvider, useConfirm, type ConfirmOptions } from './Confirm';
export { toast } from './Toast';
export { Drawer } from './Drawer';
export { Checklist, ChecklistItem, type ChecklistState } from './Checklist';
export { ChatMarkdown } from './ChatMarkdown';
export { Article, type ArticleImage, type ArticleLang, type ArticleProps } from './Article';
export { FloatingChat, ChatHeader } from './FloatingChat';
