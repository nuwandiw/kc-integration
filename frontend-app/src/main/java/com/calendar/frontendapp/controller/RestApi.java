package com.calendar.frontendapp.controller;

import com.calendar.frontendapp.util.CalendarGenerator;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Map;

@RestController
public class RestApi {

    @GetMapping("/api/calendar")
    @ResponseBody
    public Mono<Map<String, Object>> calendarData() {
        return Mono.fromCallable(CalendarGenerator::generateWeekCalendar);
    }
}
