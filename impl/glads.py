from preprocessor import PcapPreprocessor, PcapPreprocessTask


class _GladsTask(PcapPreprocessTask):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class GladsPreprocessor(PcapPreprocessor):

    def __init__(self):
        super(GladsPreprocessor, self).__init__()

    def create_task(self, **kwargs) -> _GladsTask:
        return _GladsTask(**kwargs)
