//! A trend over time: one small point per audit, numbers only. A point holds no address, name or anything
//! else that identifies a network; it is a few measurements and the time they were taken.
use super::model::{Report, WifiBand};
use serde::{Deserialize, Serialize};

/// The oldest points are dropped past this many.
pub const MAX_HISTORY_POINTS: usize = 500;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryPoint {
    pub at: String,
    pub score: Option<u32>,
    pub coverage_percent: u32,
    pub link_rate_mbps: Option<u32>,
    pub signal_dbm: Option<i32>,
    pub router_ms: Option<u32>,
    pub isp_ms: Option<u32>,
    pub band: Option<WifiBand>,
}

pub fn point_from(report: &Report) -> HistoryPoint {
    let speed = &report.checks.wifi.speed;
    let latency = &report.checks.latency;
    HistoryPoint {
        at: report.generated_at.clone(),
        score: report.score.provisional,
        coverage_percent: report.score.coverage_percent,
        link_rate_mbps: speed.link_rate_mbps,
        signal_dbm: speed.signal_dbm,
        router_ms: latency.router_ms,
        isp_ms: latency.isp_ms,
        band: report.checks.wifi.band,
    }
}

/// The points with `point` added at the end. A point with the same time replaces the old one, and the
/// oldest are dropped past the limit.
pub fn with_point(mut points: Vec<HistoryPoint>, point: HistoryPoint) -> Vec<HistoryPoint> {
    if points.last().is_some_and(|last| last.at == point.at) {
        points.pop();
    }
    points.push(point);
    if points.len() > MAX_HISTORY_POINTS {
        points.drain(..points.len() - MAX_HISTORY_POINTS);
    }
    points
}

/// One measure across the points, oldest first. None where a point did not have it.
pub fn series(points: &[HistoryPoint], pick: fn(&HistoryPoint) -> Option<f64>) -> Vec<Option<f64>> {
    points.iter().map(pick).collect()
}

/// The smallest and largest known value.
pub fn range(values: &[Option<f64>]) -> Option<(f64, f64)> {
    let known = values.iter().flatten().copied();
    let min = known.clone().fold(f64::INFINITY, f64::min);
    let max = known.fold(f64::NEG_INFINITY, f64::max);
    (min <= max).then_some((min, max))
}

const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

/// A line of bars, one per value, scaled between the smallest and largest. A gap shows as a dot.
pub fn sparkline(values: &[Option<f64>]) -> String {
    let Some((min, max)) = range(values) else { return values.iter().map(|_| '·').collect() };
    values
        .iter()
        .map(|v| match v {
            None => '·',
            Some(_) if max == min => BARS[3],
            Some(v) => BARS[((v - min) / (max - min) * 7.0).round() as usize],
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(at: &str, score: Option<u32>) -> HistoryPoint {
        HistoryPoint { at: at.into(), score, coverage_percent: 50, link_rate_mbps: None, signal_dbm: None, router_ms: None, isp_ms: None, band: None }
    }

    #[test]
    fn adds_points_in_order_and_replaces_one_with_the_same_time() {
        let points = with_point(with_point(vec![], point("a", Some(1))), point("b", Some(2)));
        assert_eq!(points.iter().map(|p| p.at.as_str()).collect::<Vec<_>>(), ["a", "b"]);
        let points = with_point(points, point("b", Some(9)));
        assert_eq!(points.len(), 2);
        assert_eq!(points[1].score, Some(9));
    }

    #[test]
    fn keeps_only_the_newest_points() {
        let mut points = vec![];
        for i in 0..MAX_HISTORY_POINTS + 25 {
            points = with_point(points, point(&format!("{i:05}"), Some(1)));
        }
        assert_eq!(points.len(), MAX_HISTORY_POINTS);
        assert_eq!(points[0].at, "00025");
        assert_eq!(points.last().unwrap().at, format!("{:05}", MAX_HISTORY_POINTS + 24));
    }

    #[test]
    fn sparklines_scale_between_the_smallest_and_largest_and_show_gaps() {
        let values = [Some(0.0), Some(50.0), None, Some(100.0)];
        assert_eq!(sparkline(&values), "▁▅·█");
        assert_eq!(sparkline(&[Some(7.0), Some(7.0)]), "▄▄");
        assert_eq!(sparkline(&[None, None]), "··");
        assert_eq!(sparkline(&[]), "");
        assert_eq!(range(&values), Some((0.0, 100.0)));
        assert_eq!(range(&[None]), None);
    }

    #[test]
    fn a_point_holds_numbers_only() {
        let json = serde_json::to_string(&point("2026-01-01T00:00:00.000Z", Some(90))).unwrap();
        assert_eq!(
            json,
            r#"{"at":"2026-01-01T00:00:00.000Z","score":90,"coveragePercent":50,"linkRateMbps":null,"signalDbm":null,"routerMs":null,"ispMs":null,"band":null}"#
        );
    }
}
