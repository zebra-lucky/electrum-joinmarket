#!/usr/bin/env python
# -*- coding: utf-8 -*-

from base64 import b64decode as dc


PNG_BYTES = dc(('iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAAABHNCSVQICAgI'
                'fAhkiAAAAAlwSFlzAAAB2AAAAdgB+lymcgAAABl0RVh0U29mdHdhcmUAd3d3'
                'Lmlua3NjYXBlLm9yZ5vuPBoAAB7DSURBVHic7Z13eBXF3oDfSYeEFgglJBBS'
                'qBJC6IEAUhSkFwUFsaEICtxPr9+n2EVEvffxCiqKKKigF8RQBQtFWghFAqGX'
                'JJRQQgKhpbf5/jgJppw9Z3bPSUPe59k/cnZ2drLz29mZ+TW4y13u8vdFVHQD'
                'yhopcQKaAXUBD6A24F5w1CgodgtIKziuF/ydApwWgtzybnN5cscIQEFHtwfa'
                'As2BFkBLIABwNlhtNhAPHAdOACeBg8B+Iciztc2VgSotAFLiD/QrctQpp1un'
                'AVHAxoJjvxDkl9O9/75IiaOU3Ccli6UkWUpkJTmSpOQ7KekvJQ4V/Zz0UCVG'
                'AClpBYwBHgP8KrY1VrkI/AQsEoIDFd2YKouUOEnJo1LyZyV4w40ee6VkfMH8'
                '5C4qSImLlEyQkhOVoAPtdZyWkulS4lbRz7fSIiXVCh5SQiXosLI6zknJVCmp'
                'VtHPu1IhJUMK3pKK7qDyOs5LyYMV/dwrHClpJiVrK0GHVNSxWsqKndRWyCpA'
                'SlyAl4AZQHV7138r053YpCbEJvsSn+TLiNBNNG9wRlcd3+8exPmUhvjXTyDQ'
                'K4HA+ueo4ZZm76YCpAOzgH8LQXZZ3MAS5T47lZIg4EcgxF51pme7se9sa3ac'
                'CmV7bChHLgSRL/+S7T6tdumu8/CFIJbsGnz7bwchCax/lk5+R+gRFE3PoH3U'
                'rJZqj+ZXxyQAo6VkjBCcskelqpSrAEjJWOBL/tqDN8yNjBqsjenFyv19iT7b'
                'mtx8R82yNzM8dNd/+aZnsb/zpeDkZT9OXvbj+92DcHLIo6PfEYa338SQ4K32'
                'EIb2wJ9S8owQLLO1MlXKRQCkafnzMTDJlnpy85zYcrIjEfv6s+FoN7JyXZSu'
                'u3yzru57Jd7wstyWfEd2xQezKz6YN1c/x31tohgZuoHeLfbi5GBYTVATWCol'
                'vYAXhCDTaEWqlLkASElTYDXQzmgdWbkuLNs7gM+3jOH8tQa6r798s57uay5e'
                'r69cNivXhbUxvVgb0wufOolM6b2MMZ1+xcUpR/d9C5gMdJWSEUJw1mglKpTp'
                'JFBKWgO/AT5Grk/PdmPpnoF8vnUMiTf0d2Ihw0I28+kj7ymXT7rpSYd3fzR8'
                'P4B6HteZ0G0NT4f/hIdbutFqLgEDhOCgTY2xQJkpLqQkDNiBgc6XUrB0z0DC'
                'Zn/Pm2ueM9z51ZyzaOMdR/2aKbquS82qzpB2W2njHUc15yxD976SWpuPNkwg'
                '/MPvWLZ3AFIaetcaAX8UPMsyoUxGACkZhGmmr3uJd/RSAK+umMafZ9vovm89'
                'j2t0C4ihe+B+uvnH0KzeBYSQuuspipSC+Cs+RMW1Y2dce6Li2nEltbbueoJ9'
                'TvLeiDm08z1hpBnpwENCsM7IxZawuwAUzPS/Q6cRRlp2Nf716xN8u3OYxRl9'
                'SRrXTmJk6EaGtNtCy4anbe5wa0gpOJboz9oDvVmxvx8Xr1ueLBbFySGPJ7qv'
                '4p/3L6K6i+75XQ4wQQiW6r3QEnYVACnpC6wH1KbnBZxKasLkJW9wItFPqbyb'
                'cxZD2m1hdIcNdPWPwaGMO12LfCmIigshYl9/1sT0Vl6VBHgl8Pn4mbRqFK/3'
                'ljnAMCH4Re+FWthNAKSkE7AZk92dMhHR/ZmxYjrp2dYVZe4uGYzt/AuTey+j'
                'Qc2rBltaNlxJrc3iqKEs2D6KW5nuVsu7OmUz44EFPNljpd5bpQP9hWCnkXaW'
                'xC4CICUtge2A8mwtI8eVlyP+hxXR/ayWdXfJ4Jley3my+0pqV79lQ0vLnpS0'
                'Wny9YyRfbR+lJNSjO2zgvZEf651sXgF6CIGhCUVRbBYAKWkMRAJNVa+5nl6D'
                'Jxa9qzTR6986ineGfYpPncs2tLL8SbxRjw9+fYqf9vW3WraT32EWPfE6tarp'
                'Eu4zQHchuGiwiYCNAiBNli5bgO6q1yTd9OTRr2dz9FKAxXJN615k5rBPubfl'
                'HluaWOHsiG3P66umEZvka7FcUIOzLHnqZbxrJ+upfjcQLgSGd5xsFYAPgP9V'
                'LX/2qjfjvnqfs1e9LZYb3WEDs0bMMTJTrpRk5rjy1popfL97kMVyPnUus2Ti'
                'ywR4JeipfrYQzDDaNsMCICUDgXWqdZy+0piR8+ZYXEO7OWfxzrDPeLjzeqPN'
                'qtSoTHjreVxnxZTpNKt3QbXafGCQEPxqpE2GBEBKGgL7gYYq5ZNuejJ83lwS'
                'UrSLB9Y/x4IJbxJYX5f0WyQ335GD55tz7JI/8ck+xCU34VxKQzKy3biVWZ3U'
                'LNNs3cM1DQ/XDKq5ZOJX9yL+XgkEeCXQqtFp2vqctEW5U4pTl5vy9HdvEZes'
                '/Unw9Uxk1ZRpenYwk4H2QqAsNYXoFgBpsnvfDPRSKX8r053Rn39k8Zsf2uQY'
                '3z45wy4z/IvXvVh3sBeRce3ZHd+W1Czb7E08XNPp6n+Q7oH7GRS8jUa1dH2j'
                'zZKSVovHFs7iQEJLzTKtG8Xx0+QX9BihbAH6CIGuTREjAjARWKBSNjvXmXFf'
                'fcCu+GDNMn1a7ubz8TNt+t5n5riy9mAvIvb1JyoupJgxiD1xEJLugfsZGbqB'
                'wcHbcDOoJwCTomvS4jfZcqKTZpluATEseeplPVrFiULwtZ526HpSUuKJyU9O'
                'af/z9yNhPP/Dq2TkuJo9PzTkD+aM+QAnR2P+l6mZ1fk2aihfbR9taH/eFup5'
                'XOPpnhFM6LYGD1dj2r7cPCemLX2ZtTG9zZ4fcM8O3h46D+/aSapVXgVaCsEV'
                '1Qv0CsACYKKeay5cr8+sdZNYG1P8i9Gn5W6+fuxNQ52fk+fEl9tGM2/LWEPW'
                'PvakVrVbPN/nv0zsscLQ/5Kb58Tji95l68mOt38LanCWWcPn0i0gxkiT5gvB'
                's6qFlQWgYKt3FwZVyEv3DOS1VVPJynUhxPc4Sye9hLtLhu56dscHM2PlNE5e'
                '9jPSjDLD3+s87w7/hPCgfbqvzchx5ZEvP+TPs20Y3n4zH4z6yJZPYj4QJgS7'
                'VQorCUDBxG8vEGq0VQCHzjfn3fXP8MX4d6hT/aaua7NyXXh7zWSW7B5sVLde'
                '5gghmdBtDa8Pno+rkz4D35S0WvxxvDOjOmywR1P+BDqrTAhVBWAkEGFrq8A0'
                '5OkdKuOTfZjy/escuWh597CycE/jWOaNm6lnLV8WDBOCNdYKqQrAXqCj1YJl'
                'wNaTHXl28Rs2L+fKGw+3dL589C3Cg6Irqgl7hKCLtUJWv+dScj8V1Pm/HO7B'
                'k9/MrHKdD6YVymML32PNgXsrqgmdpcSqqtXqCCAl24BwuzRJB4ujhvDaqmll'
                'tqYvLxyEZNaIOYzv+nNF3H6LEFiUQIsjgJSEUwGdv/pAnzui88FkNTRj5XQl'
                'tXAZ0FtKelgqYO0TMM2OjVFiR2x7XvjxpTui8wuRUvDSTy8WW+uXI1MtndR8'
                'ylJSC5Ndern5sscn+zBo7rwq+c1XwcMtnV+mT8avbrmuDjKBRkJw3dxJSyPA'
                'WBQ6X8XsSYWsXBcmL3n9ju18ME0Mpyx5jexco1HrinNBzXvJDRitddKSADyq'
                'UvvUH2ZY1Gqp8vaayVathO4EDl0IYubPNrlIcivTnVdW/IOpPyjbgWj2pVkB'
                'kJIAsO6NciqpCb8fDWP4Z3N5d90zZGoofayxOz6YJbsHWy94h/Bt1DCi4vS7'
                'SubmO7Jyf1/u/fdCluwazN4z91g1NSsgXEqamTuhNQKMR2GJGLHvPgDy8h2Y'
                'v/Uhev3rG77eMVLXZyEnz4mXV/yj0m7vlgVSCl5bNZXcPDXfXCkFi3cNoeeH'
                '3zLtv68U83ZeEa20uhDAI+ZOaAnAQGs15kvByv19i/128boXb62Zwvu/qCsM'
                'v9w2mtikJsrl7xROXvZjYeQIpbJCSKLPtjZrUbUiup/qimmAuR9LCYCU1EBB'
                '6bMzLkTTLWrgPdtVGkRqZnXmbRmrVPZO5JPNjyhPekeGmlcSXbhen90WDG6K'
                '0EXK0k475sagcBT8+lYf6GP298a1k+jir+bN/E3UMN36fCeHPMZ0sm7/uO1U'
                'B7NvTLDPSdo2Vo/Ccj29BusO9bRa7oG223VpOGPOt+DwhUCW7BrMs72su6J3'
                'D9yPd+1ksy/dqgN9VWwHnIEeUNx41JwAmO/ZEuw4ZX6QGNlhg5KvXlauCwt3'
                'qA2BRXFyzOX9Uf+xWm7S4jfNCsB9rXcyvd8S5ftl5bqw6XgXixNcZ8dcPh77'
                'vi7vng9/fZLDFwKZv/VBHg9bbdW8zEFIhodsMjtibjvZQfW2vSkhAObmAFa1'
                'F2evemtG6hjabotSS9bE9Cb5lqf1ghWMq1M2HZoetVimo98RG+II1FEaYQCG'
                'aDzb89caWLS4LkKpl7uYABTs/lldn+yMMx/gq57HdVoohmOLqJi9cUOEBViO'
                '+WztvDUi9ln3jwRo4x1HXfcbZs9FxrZXqSJUSmoW/aHkCNAasOqcHxlrXgDC'
                'Avcr+ecn3qjHrnjDIYPKnbDAshWAyNhQLlkJSgWm1UA3jXtFqT1PR6BV0R9K'
                'CkBzlVr2nG5r9nfVB7E2pjd5+VUnrH6I73HNOD/VnLMI8T1uU/35UrD+kJrS'
                'VesZ63ihWhT9o2QvWN3TTc2srimt3fzVrFgj45SGq0qDk0Menf0OmT3Xudkh'
                'W6KB3UZxCNccAS5e91JdUhZ7yUsKQAusoOXSVM05Cz8FG7jcfEd2a4wglQGt'
                'HcnuGp8BrQ7Ru7O5Kz5YaVT09zqvuWI4faWxyq0sjgBWPwFaAuDvdV5p+Xfo'
                'fHNSMyuvxu+Ehrm5VkdrCcaxRH9d972V6c7hC0FWyzkIqWlsGm/B37AI5gWg'
                'wPQ70NrV8VfMR33zV3RpPnpJ34Mpb7SG4jbesXiWmIHXcEujbeOTZsvv1Jgo'
                'W+KY4rPxr3fe7O9xyUoR+YKk/EvPU3QE8ACsqvPiNW6i6tNuySu2MqC1xHUQ'
                'ki7Nis8DuvofxNHBfLKwnQa0farPxl/Dg1qrb0rghil3IlBcAJQCOF9Pr2n2'
                '9yaeiSqXqw5TFcbJxKZcSTWffa7kclDrs5B005O4ZP0KLlUBaOp5yezvOjbW'
                'bqsTS44AVknLMm8k5KHoxpyQoj/Wb3kiEUTFmVeudA/YX/xvje+/0VWO4m6e'
                '5pL0msbLaQazAqA0AqRlawiAq5qfn0oItYomSuMzENTg7O3wdHWq36RlQ/Nx'
                '/rQ+I9ZQ1QxqeSPfyFCOwn+7E3QLgNYM3l3RRVpLgCoTlt7gQq1bWMABzVWP'
                '6pq+JKoC4K7xsumwNbw917PbCKDq6Zuu8QmpTMQn+2hudhXuxGltD1+4Xl95'
                'KC9JquKz0RoBsmwUgLsUQctmr3ugaR4QVmI+UIiWmrw8MBInuagAKAXo0XrT'
                'VYf26opzBVvJUbS300JL4dXE8xIdmx7RDGZl9PsP6vMorU+Fi6PylvTtrUTd'
                'AqA1A01TnsCUjwDY6l9gqSNfvP8bQ9dZQzXUjNZKzFVdJ3E7eEHR18SmEUD1'
                '+2WKelX6+yqEpGHNKzSte4kmnhfxrp3MxxtLm7M7K8YWsHW7+fy1hiSkNMTX'
                'zP5Gj0Dzw39csq9NmU1UBUBLuHUkrrq9Zi8qAEpXa81AUxWXd751EjmR6Mej'
                '3dYS4JVA07oXaep5iSZ1LxWLqiGl4JPN40opSFTt7uzhYbQzLoQxnurxF215'
                '+wF8NTZ4SnIrw/yz1jIWMcPtWHe6R4A6Gjc5pzjz9fdKgGNdmdJ7qcUA0EJI'
                'GtS8WsoIsn4NteCJ9thviIxtr2SAWoiR/f+iBHiZ3+Mvyblr5p91XY9rqre6'
                '/RCLvl6pYD1NmZYmSnUbs1BncC6lkdWyJXfeAKXIWbcy3e0SNk7PGy0LkkfY'
                'gqo+JV7DG8hfTYAy4C9H0dsCIAT5QJy1q7UaqbrH36rRaQAlf8IX7vuOhrX+'
                'Cnnn73Wep8Kthyo6nmjWC0o3l2/WVRbs44nNuJpWy6b7qWYQ0WqT4ghyqmjw'
                'qJJrpROAxSD+2gLgQ74UVm0C2vqcxMMtnc3HOzOlt+X0Nz51EvnjxSfZdToY'
                'F8dcuvgfVIq+ZetQXKyuuBClN9PW738NtzTuUfBXyJeCMxrR1hVV8sX01yU3'
                'gqxmoPD3Om92wyEjx5UzChYpTg55dG12kL2n23LmqvXyHm7p9Gu1i57N/1Tq'
                '/HwpWLFfzcpWBVVhslUAuvrHaKqWixKf7GPWR0FYMBQpQbE+1i0AHq7pNKpl'
                'PhKp6kMIC9xPvhR8vGG8Unk9RET3V9WLKxEVF2LVvCsv38FiPGQVtJaW5tpj'
                'Du9ayarLSIsjgHnzlhJ0bmbeQFJVAIYEb8XRIZ+I6P78fsR+ORHjkn15e81k'
                'u9UHcDWtlqaZWCFHLgbaFLLWQUgGtt2hVFZL0dRV0SAXU6znv+5d4uRRwGpw'
                'fHOzc1B7WwAa1rpy24J46n9nGPKVL8nJy348/OWHelSiylj7DBjV/hUSHrRP'
                'KQy9lELT/l8xrnAelgRACG4AVmvSutmV1NrKxpCjOvwOmELMPPLVB8zbMtbQ'
                '/n1evgM/7H6AoZ98ouRcYQRrBh62fv9Hhm5UKnfkYgApGisNLeOUEkQLQbGd'
                'NHNPfDNW3MOb1r2IT53LZv0D1x7oTetGVleTDGm3ldm/PE3STU9y85yYvX4i'
                'S3YNZmynX+jfOooWDU9bXFEk3fRk3aGefL97sHLCSTAZTVjagzAXtGF3fFvO'
                'XvU2O/nNlw7sPX1Pqd9z8pws3ud6wUjlVSOFB9qqudNreWT7eibiU0fJJG9z'
                'yR9KjddS8gBYz1H70k8vsnRP6TgSDWtdYdcrjyjNaOdtGcvs9eaDSXi4puPr'
                'mUjj2km4OWfh5pxNRrYr19JrEpfsWyxKRlXm9cHzeabncqvl8qWg63s/mB3l'
                'xnVZp+QxjSkT+W9FfzA3AmzHlKLUonXBsJDNZgWg0O+vu8Ks9rGw1Xyx5SGz'
                'tmypWdU5dslf2VS6KlKn+k3GKUYQteQ/OLz9JpUqsjFlcy9GKYMQIbiFKdy4'
                'RcICDmjmuFP1/HV3yWDKvXbNhVylmNb3e2VLqt8Om0/N2Lh2kuaqrAS7haCU'
                '5a6WRZDV5MQOQjLCjOQ1q3eBTs0OK7tGTQyPMJJEucrTouEZHg9brVz+1cHz'
                'zWZQHRm6UTV5tlmtltlekhI/IF7rfCGnkprQ598LAfCuncxrg75gUPA23dm8'
                '95xuy+gvPvrbRAoTQvLjpBfpqhhKpyiZOa58tGECC7aNJjffkT/++YRKqj0J'
                'BAjB6ZInzK67hOCMlESC5UDDQfXP0dnvEK2843l54NeGkyd1bnaICd3W8O3O'
                'YYaur2o82X2loc4HU3LNGQ8sYFDbbczdNE41z+I2c50PlmMFPwPMt1bzxete'
                'evPdmiUr14Xhn83l8AWr7olVmmCfk6x6bpqyZZMl0rPdVHMLaaaTq1TBos9c'
                'bczAOZ9Xau9hW6hZLZVfpk+miaLlj50wFiy6YFewXLMc+NW9wNePvWGXgAuV'
                'DWfHXL4YP7O8Ox9gjVbng3W/gLl2boxVwgIOMG/cu0obSVUFByGZ+/BsQynl'
                '7IDFPrQoAEKwA9hm1+YocH+bSGYO/0T3aqIy4iAks0f+h8HBWyvi9luEINJS'
                'AZWcQfejsYYsa3493IPnf5hBVq5LRdzeZpwdc5kz9n3N+H7lQH8hsKhpUk0b'
                'twfQznJchmw/Fcozi9+qchPDmtVS+fLRt5W2xMsI+6SNK2C2jY0xTHhQNBv+'
                '52naNzlWUU3QTdvGp1g37TndnW+rO1sJ3lUppCoAqwCbZzBSCpbtHaip09bC'
                'p85lfnr2BR4PW2XIAbK8EELyVI8VrH5+qu68QFdSazN2/r84eF4pVKM19qC4'
                'gtOTPLojsBuDHsWpmdV5cflLrD8UTjvfEyyb9E9DyaP3nG7Lqyun2c302160'
                'ahTPrBFz6OR3RPe1GTmuPPzlv9h3tjUuTjnMHPYJj3RZb7Qp9k8eXYiUzAee'
                '0duirSc78trKqcWsgHu32Muix183nHJ9YeQIPt38sJ6wKGWCp/sNpvb5gce7'
                'r8LJwao1XSly8px4bOEstp8qHvH7gbbbeX3wFxa9pzT4XAimqBbWKwCemGzK'
                'lGyvElIa8vrqqWw6Zn4uMqTdFuaOfd+QEIDJJX1x1BDmb31QM7BTWVG/ZgqT'
                'ei5nXNefDY1kYOr8af99hZ8P9jJ73s05i8/HvUu/1lGqVV4FWgqBebNtM+ia'
                'dQhBipS8AnylUr5BzatkZGtHnlsb05ubGR58OeEt1T3tYri7ZPBsrx95PGw1'
                '6w71JGJfPyJjQ8ss6aSjQz7dA6MZFbqRQcHbdKeIL0padjWe/vatUm9+UTo0'
                'PUqvFnv1VPu/ejofdI4AcDug5CZMyQescivTnQe/+Mhi6vcQ3+N8++SrpQIx'
                'GiHxRj3WHepJZGx7dsUH2+wkWsMtja7+MYQHRfNA2+23g0TZwtW0Wkz4erbF'
                'Cd89jWNZPukFzXgMZvgD6FvU7UsFQ6+KlDQADgBKLsFX02oxct4ciw4bAV4J'
                'LJjwFkENzhppklny8h04fCGIo5cCiE/2IS7Zh3Mp3qRluXEr053ULJNweLim'
                'UcMtDXfXTJp4XiTA6zwBXgm09o6jjXesXbelTyT68fR3b1uM69vE8xKrnpuO'
                'l6InNCZ37xAhuKi3PYbHSikZgMl4VGlVcOZqY0Z89rHFb7WbcxavDPyKJ3us'
                'NNqsSk1EdH9mrJhuMa1ePY9rrHzuH3qWkfnAQCH43UibbPpYSsls4GXV8udS'
                'GvHIgg84q+HcWMio0A3MGjnX8OSqspGWXY1XIv5RKs1eSXzqXGbJxJeV3cQL'
                'eE8IXjXaNlsFwAnTt8ei5VBRkm568ujXs62miW3ieYl3hn1K31ZKy9lKy8Zj'
                'XXlj9fNWQ8c1b3CGJRNfUfIQKsIuoKcQGNaf2zxdlhJvIBLwU73mRkYNnlg0'
                'k71nSjtUlKR/6yjeGfaZquNDpeHSDS/eXjNZKSFU52aHWPT463pi/ACcBroL'
                'gU0GBnZZL0lJc0w258q+WZk5rsxYMZ3lBelnLVHNOYuJ4RE8FR6hJw5OhXAl'
                'tTYLto1mYeQIpVzKD3X8lVkjPrGaNq4EyZg6Xz0BogZ2WzAXbBX/gWLQ6UJU'
                'JkaFVHfJ5OHO65nUa7neobLMuZJahwXbRrEocgQZCh3v5pzF20M/M7Llmw70'
                'EwLl3SFL2HXHREr6AOtRyDtQlNgkXyYveUN5f9/FKYeh7bYwMnQD3QP3V5jh'
                'SL4URMa2J2Jff9Ye7K0cqzewfgKfj3+Hlg3NGupaIgcYKoT97DPsvmUmJWOA'
                'xSikny1KerYb//79cRbtGEFuvtXMdbdpVCuZEe03MTTkD1o3ii9zbWG+FBy9'
                'GMCamHtZub+vrriATo65PNVjBS/e962RRJM5wKNCsEzvhZYokz1TKekHrEAx'
                'AHVR4pJ9eW3lNHYY8Lmv636DbgEHCAs4QLeAA8p5jCyRLwXxyT5ExYUQGdue'
                'qPh2utXZYJrozRox18hbD6Zh/0EhMKwi1KLMXHGkpBsmnbTu/LBSCpbvu5/Z'
                '6yfaFO7N1SmbAK8E/L3O838DFiplNSvkrTVT2BkXQnyyj00maV41Unjlga8Y'
                'HbrB6OiUAgwSgl2GG2GBMvXFkpJWwG+AoTwx2bnOLN93H3M2jrc5+MOBN0fp'
                'WkFM+f411sb0Nny/eh7XeLpnBE90X2k4rzAmv4wBQmDMjUgBu9oglUQIjklJ'
                'D2AlVoJOmMPFKYdxXdbxYIffWbZ3APO2jOG8RpRMS9SvmaJ7+ahzN+42vp6J'
                'TOm9lIc6/marf8M+YIQQGGuIImUqAABCcE5KwoAPgWlG6nBxyuHRbmt5pMs6'
                'dsaFsCK6P+sPhSstHQEa19ZtVEH9msqKGFydsunZfB8jQzcyoE2kYfuGIiwG'
                'JglBme+Fl7kAAAhBFjBdSnZgsiUwZMbj6JBPeFA04UHRvDPsU34+2IuV+/uy'
                '90wbs6FdCtEKa2eJhlbUvs6OuXTyO8yI9psYFLytIAq6zdzA5Mf3kz0qU6Fc'
                'BKAQIVheYGK+DKybLFuihlsaD3dez8Od15OR48qfZ9qw41Qoe8/cw/6ElsUE'
                'Qoda9TY13Ypvyzo65NPaO5bOfofp6HeEXs3/tFenFxINjBGCWHtWao0KcciX'
                'EmfgReA1imSwshepmdWJS/YlNrkJcck+NPFMZGwnqzEvinHskj9rD/Yi0CuB'
                'gIJDh3GGHtKAd4D/2KLUqZJISVMpWSUl8m96rJAS/Rkm7zSkZLCUxFeCDimv'
                'I05KBlX0c69USImblDwvJWcrQQeV1XFWSp6TErXly98RKXGWkglScrwSdJi9'
                'jngpmS6lPiXZ3xopcZKS8VKytxJ0oNFjr5SMkxJ17VY5UyXCcknTlvIYYAJQ'
                'uXzCSnMBiAAWCYFSAN+7KCIlDlLST0q+kZLLleANLzwSpWSRlPSRsmplY60S'
                'I4AWUuIP9Cs4+mJA82iQVEwGmRsLjmi9DhmVhSotAEUp+M62A4KBFkBzoCUQ'
                'CBjV52YDpzBlUjmBKaHGQSBGCOt5FaoCd4wAaFEgGH5AI6BuweEOlAw5korJ'
                '8OIqJh38JeDMndLRd7nLXe5Smv8HJSpRvyVwl84AAAAASUVORK5CYII='))