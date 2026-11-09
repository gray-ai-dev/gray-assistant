import type { ReactNode } from 'react';
import { Button, Calendar, CalendarCell, CalendarGrid, DateInput, DatePicker, DateSegment, Dialog, FieldError, Group, Heading, I18nProvider, Label, Popover, Text } from 'react-aria-components';
import { fromDate, getLocalTimeZone, toCalendarDateTime, type CalendarDateTime } from '@internationalized/date';
import { CalendarBlank, CaretLeft, CaretRight } from '../components/icons';
import { cx } from './cx';
import type { DateTimeFieldProps } from './DateTimeField';

const zone = () => getLocalTimeZone();
const toValue = (ms: number | null | undefined) => ms == null || !Number.isFinite(ms) ? null : toCalendarDateTime(fromDate(new Date(ms), zone()));
const toMs = (value: CalendarDateTime | null) => value ? value.toDate(zone()).getTime() : null;

/** The React Aria parts of `DateTimeField`, loaded with the first date field a page shows. */
export default function DateTimePicker({ label, hideLabel, optional, hint, error, value, onValueChange, min, max, required, disabled, granularity = 'minute', className }: DateTimeFieldProps) {
  return <I18nProvider locale="en-US"><DatePicker className={cx('ui-field ui-date-field', className)} value={toValue(value)} onChange={next => onValueChange(toMs(next as CalendarDateTime | null))}
    minValue={toValue(min) ?? undefined} maxValue={toValue(max) ?? undefined} granularity={granularity} isRequired={required} isDisabled={disabled} isInvalid={error ? true : undefined}
    shouldForceLeadingZeros hideTimeZone>
    <div className={hideLabel ? undefined : 'ui-field__label-row'}>
      <Label className={hideLabel ? 'ui-sr-only' : 'ui-field__label'}>{label}{optional && <>{' '}<span className="ui-field__optional">(optional)</span></>}</Label>
    </div>
    <Group className="ui-date-field__group">
      <DateInput className="ui-date-field__input">{segment => <DateSegment segment={segment} className="ui-date-field__segment" />}</DateInput>
      <Button className="ui-date-field__button" aria-label="Choose a date"><CalendarBlank size={16} aria-hidden="true" /></Button>
    </Group>
    {hint && <Text slot="description" elementType="p" className="ui-field__hint">{hint}</Text>}
    {error && <FieldError className="ui-field__error">{error}</FieldError>}
    <Popover className="ui-date-popover" offset={4} placement="bottom start">
      <Dialog className="ui-date-dialog">
        <Calendar className="ui-calendar">
          <header className="ui-calendar__header">
            <Button slot="previous" className="ui-calendar__nav" aria-label="Previous month"><CaretLeft size={16} aria-hidden="true" /></Button>
            <Heading className="ui-calendar__heading" />
            <Button slot="next" className="ui-calendar__nav" aria-label="Next month"><CaretRight size={16} aria-hidden="true" /></Button>
          </header>
          <CalendarGrid className="ui-calendar__grid">{date => <CalendarCell date={date} className="ui-calendar__cell" />}</CalendarGrid>
        </Calendar>
      </Dialog>
    </Popover>
  </DatePicker></I18nProvider>;
}
