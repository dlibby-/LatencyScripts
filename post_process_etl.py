#!/usr/bin/python
import sys
import re
import argparse

# ETW event names - these are both used as constants for comparing event names
# as well as in the regex filters that affect which events we start looking at
DWM_RENDERANALYSIS = r"Microsoft.Windows.Dwm.Interaction/RenderAnalysis/"
DWM_INTERACTIONANALYSIS = \
    r"Microsoft.Windows.Dwm.Interaction/InteractionAnalysis/"
DWM_TOUCH_DEBUG_EVENTS = \
    r"Microsoft-Windows-Dwm-Core/TOUCH_INTERACTION_DEBUG_EVENTS/win:Info"
WIN32K_POINTER_FRAME_COMMIT_STOP = \
    r"Microsoft-Windows-Win32k/PointerFrameCommit/win:Stop"
WIN32K_POINTER_MESSAGE_RETRIEVESTOP = \
    r"Microsoft-Windows-Win32k/PointerMessageRetrieve/win:Start"
WIN32K_APP_MSGPUMP_START = r"Microsoft-Windows-Win32k/AppMessagePump/win:Start"
DMANIP_ZOOM_TO_RECT = \
    r"Microsoft-Windows-DirectManipulation/Manipulation_ZoomToRect/win:Info"
DMANIP_LAYERCOMMIT = \
    r"Microsoft-Windows-DirectManipulation/Manipulation_LayerCommit/win:Info"
DXGKRNL_VSYNC = r"Microsoft-Windows-DxgKrnl/VSyncDPC/win:Info"

class ProcessingType:
    EdgeTouch = 0
    EdgeWheel = 1
    ChromiumTouch = 2
    ChromiumWheel = 3

def get_processing_type(args):
    if args.browser == "edge":
        if args.input_type == "touch":
            return ProcessingType.EdgeTouch
        else:
            return ProcessingType.EdgeWheel
    else:
        if args.input_type == "touch":
            return ProcessingType.ChromiumTouch
        else:
            return ProcessingType.ChromiumWheel

def get_event_filter(processing_type):
    return {
        ProcessingType.EdgeTouch: r"(RenderAnalysis|InteractionAnalysis|" +
            r"TOUCH_INTERACTION_DEBUG_EVENTS|PointerFrameCommit|" +
            r"PointerMessageRetrieve)",
        ProcessingType.EdgeWheel: r"(" + DMANIP_ZOOM_TO_RECT + "|" + 
            WIN32K_APP_MSGPUMP_START + "|" + DMANIP_LAYERCOMMIT + "|" + 
            DXGKRNL_VSYNC + "|" + DWM_RENDERANALYSIS + ")",
        ProcessingType.ChromiumTouch: "",
        ProcessingType.ChromiumWheel: ""
    }.get(processing_type)

def main():
    parser = argparse.ArgumentParser(description=
        'Post-process etl files that contain events related to' +
        'browser scrolling.')
    parser.add_argument('--browser', required=True, choices=['edge', 'chromium'])
    parser.add_argument('--input-type', required=True,
        choices=['touch', 'wheel'])
    args = parser.parse_args()

    processing_type = get_processing_type(args)
    event_filter = re.compile(get_event_filter(processing_type))

    filtered_events = []
    for line in sys.stdin:
        if event_filter.search(line):
            event = parse_event(line)
            if event is not None:
                filtered_events.append(event)

    process_filtered_events(filtered_events, processing_type)

def parse_event(line):
    fields = line.split(',')
    if (fields[1].strip() == "TimeStamp"):
        return None;

    return {'name': fields[0].strip(), 'timestamp':int(fields[1]),
        'thread_id':int(fields[3]), 'raw_fields':fields }

def process_filtered_events(filtered_events, processing_type):
    if (processing_type == ProcessingType.EdgeWheel):
        process_edge_wheel(filtered_events)

def process_edge_wheel(filtered_events):
    zoom_to_rect_events = [
        (x,index) for index, x in enumerate(filtered_events)
            if x['name'] == DMANIP_ZOOM_TO_RECT]

    for event, index in zoom_to_rect_events:
        i = index - 1
        thread_id = event['thread_id']
        interval_start = 0
        commit_timestamp = 0
        while i > 0:
            candidate_event = filtered_events[i]
            if candidate_event['name'] == WIN32K_APP_MSGPUMP_START and \
                    candidate_event['thread_id'] == thread_id:
                interval_start = candidate_event['timestamp']
                break
            i -= 1

        if interval_start == 0:
            raise ValueError("No MessagePump/Start for " + event['name'] +
                " with timestamp" + str(event['timestamp']))

        i = index + 1
        while i < len(filtered_events):
            candidate_event = filtered_events[i]
            if candidate_event['name'] == DMANIP_LAYERCOMMIT:
                commit_timestamp = candidate_event['timestamp']
                break
            i += 1

        if commit_timestamp == 0:
            raise ValueError("No LayerCommit for " + event['name'] +
                " with timestamp" + str(event['timestamp']))

        next_vsync_count = 0
        while i < len(filtered_events):
            candidate_event = filtered_events[i]
            if candidate_event['name'] == DXGKRNL_VSYNC:
                next_vsync_count += 1
                if (next_vsync_count == 2):
                    interval_end = candidate_event['timestamp']
                    break
            i += 1

        if (interval_end == 0):
            raise ValueError("No end interval (2 VSyncs past Commit) for "
                + event['name'] + " with timestamp" + str(event['timestamp']))

        print("Latency (us) : " + str(interval_end - interval_start))

    render_analysis_event = [x for x in filtered_events
        if x['name'] == DWM_RENDERANALYSIS][0]
    frame_rate = render_analysis_event['raw_fields'][30]
    print("FrameRate: " + frame_rate)



if __name__ == "__main__":
    main()



